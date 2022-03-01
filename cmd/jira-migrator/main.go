package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"

	jira "github.com/andygrunwald/go-jira"
	cli "github.com/urfave/cli/v2"
	yaml "gopkg.in/yaml.v2"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	cliapp := &cli.App{
		Name:  "jira-migrator",
		Usage: "migrate tickets from one server to another",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Value:   "config.yaml",
				Usage:   "The configuration file to use.",
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "inspect",
				Usage: "Inspect issues",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "host,h",
						Usage: "The host to query. Valid values are \"from\" and \"to\"",
						Value: "from",
					},
					&cli.StringFlag{
						Name:     "jql",
						Usage:    "The JQL query string to execute against the configured \"from\" server.",
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					configFile, err := os.Open(c.String("config"))
					if err != nil {
						return err
					}

					var config Config
					if err := yaml.NewDecoder(configFile).Decode(&config); err != nil {
						return err
					}

					from, err := jira.NewClient((&jira.BasicAuthTransport{
						Username: config.From.Username,
						Password: config.From.Password,
					}).Client(), "https://"+config.From.Host)
					if err != nil {
						return err
					}

					to, err := jira.NewClient((&jira.BasicAuthTransport{
						Username: config.To.Username,
						Password: config.To.Password,
					}).Client(), "https://"+config.To.Host)
					if err != nil {
						return err
					}

					var client *jira.Client
					switch host := c.String("host"); host {
					case "from":
						client = from
					case "to":
						client = to
					default:
						return errors.New("invalid host value: " + host)
					}

					if err := client.Issue.SearchPages(c.String("jql"), &jira.SearchOptions{
						Expand: "names",
						Fields: DefaultSearchFields,
					}, func(issue jira.Issue) error {
						b, err := json.Marshal(issue)
						if err != nil {
							return err
						}
						fmt.Println(string(b))
						return nil
					}); err != nil {
						return errors.Wrap(err, "unable to search pages")
					}

					return nil
				},
			},
			{
				Name:  "migrate",
				Usage: "Migrate issues from one server to another",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "jql",
						Usage:    "The JQL query string to execute against the configured \"from\" server.",
						Required: true,
					},
					&cli.BoolFlag{
						Name:  "children",
						Usage: "Set if you want to migrate all child issues.",
					},
				},
				ArgsUsage: "PROJECT_KEY",
				Action: func(c *cli.Context) error {
					var (
						config     Config
						projectKey = c.Args().First()
						errg       errgroup.Group
						issues     = make(chan jira.Issue)
					)

					if c.NArg() == 0 {
						return errors.New("must specify a project key")
					}

					configFile, err := os.Open(c.String("config"))
					if err != nil {
						return err
					}

					if err := yaml.NewDecoder(configFile).Decode(&config); err != nil {
						return err
					}

					app, err := NewMigratorApp(projectKey, config)
					if err != nil {
						return errors.Wrap(err, "unable to configure app")
					}

					errg.Go(func() error {
						defer close(issues)

						if err := app.From.Issue.SearchPages(c.String("jql"), &jira.SearchOptions{
							Expand: "names",
							Fields: DefaultSearchFields,
						}, func(issue jira.Issue) error {
							issues <- issue
							return nil
						}); err != nil {
							return errors.Wrap(err, "unable to search pages")
						}
						return nil
					})

					for issue := range issues {
						issue := issue // avoid loop closure captures

						errg.Go(func() error {
							if err := app.MigrateParents(&issue); err != nil {
								return errors.Wrap(err, "unable to migrate parents")
							}
							if _, err := app.MigrateIssue(&issue); err != nil {
								return errors.Wrap(err, "unable to migrate issue")
							}
							if c.Bool("children") {
								if err := app.MigrateChildren(&issue); err != nil {
									return errors.Wrap(err, "unable to migrate children")
								}
							}
							return nil
						})
					}

					return errg.Wait()
				},
			},
		},
	}

	err := cliapp.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

	return
}

func respErrExit(resp *jira.Response, err error) {
	dumpResponse(resp)
	panic(err)
}

func dumpResponse(resp *jira.Response) {
	if resp != nil {
		fmt.Println("X-Ratelimit-Limit:", resp.Header.Get("X-Ratelimit-Limit"))
		fmt.Println("X-Ratelimit-Remaining:", resp.Header.Get("X-Ratelimit-Remaining"))
		fmt.Println("X-Ratelimit-Reset:", resp.Header.Get("X-Ratelimit-Reset"))
		io.Copy(os.Stderr, resp.Body)
		fmt.Fprint(os.Stderr, "\n")
	}
}

type ErrorResponse struct {
	// {"errorMessages":["This Jira instance is currently under heavy load and is not able to process your request. Try again in a few seconds. If the problem persists, contact Jira support."],"errors":{}}
	ErrorMessages []string    `json:"errorMessages"`
	Errors        interface{} `json:"errors"`
}

func NewProgress() *Progress {
	return &Progress{
		migrating: map[string]bool{},
		migrated:  map[string]string{},
		parents:   map[string]string{},
	}
}

type Progress struct {
	mu        sync.RWMutex
	migrating map[string]bool
	migrated  map[string]string
	parents   map[string]string
}

func (p *Progress) MarkMigrating(from string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.migrating[from] = true
}

func (p *Progress) IsMigrating(from string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.migrating[from]
}

func (p *Progress) MarkMigrated(from, to string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.migrated[from] = to
}

func (p *Progress) MarkMigratedParent(from, toParent string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.parents[from] = toParent
}

func (p *Progress) MigratedKey(from string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.migrated[from]
}

func (p *Progress) MigratedParentKey(from string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.parents[from]
}

func (p *Progress) IsMigrated(from string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.migrated[from]
	return ok
}

func (p *Progress) IsParentMigrated(from string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.parents[from]
	return ok
}

type Config struct {
	From struct {
		Host     string `yaml:"host"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"from"`
	To struct {
		Host     string `yaml:"host"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"to"`
}

type MigratorApp struct {
	From       *jira.Client
	To         *jira.Client
	ProjectKey string
	// Config     Config
	UserLookup map[string]jira.User
	Progress   *Progress
	ApiLimiter *rate.Limiter
}

func NewMigratorApp(projectKey string, config Config) (*MigratorApp, error) {
	from, err := jira.NewClient((&jira.BasicAuthTransport{
		Username: config.From.Username,
		Password: config.From.Password,
	}).Client(), "https://"+config.From.Host)
	if err != nil {
		return nil, err
	}

	to, err := jira.NewClient((&jira.BasicAuthTransport{
		Username: config.To.Username,
		Password: config.To.Password,
	}).Client(), "https://"+config.To.Host)
	if err != nil {
		return nil, err
	}

	toUsers, err := getUsers(to, projectKey)
	if err != nil {
		return nil, err
	}

	userLookup := map[string]jira.User{}
	for _, user := range toUsers {
		userLookup[user.EmailAddress] = user
	}

	return &MigratorApp{
		From:       from,
		To:         to,
		ProjectKey: projectKey,
		UserLookup: userLookup,
		Progress:   NewProgress(),
		ApiLimiter: rate.NewLimiter(rate.Limit(100*time.Millisecond), 2),
	}, nil
}

var DefaultSearchFields = []string{
	"project",
	"summary",
	"status",
	"description",
	"created",
	"creator",
	"updated",
	"resolutiondate",
	"issuelinks",
	"issuetype",
	"labels",
	"assignee",
	"reporter",
	"comment",
	"attachment",
	"priority",
	"parent",
	"subtasks",
	"customfield_10620", // epic key
	"customfield_10621", // epic name
}

func (app *MigratorApp) QueryIssues(client *jira.Client, jql string, fields ...string) ([]jira.Issue, error) {
	var issues []jira.Issue
	if err := client.Issue.SearchPages(jql, &jira.SearchOptions{
		Expand: "names",
		Fields: DefaultSearchFields,
	}, func(issue jira.Issue) error {
		issues = append(issues, issue)
		return nil
	}); err != nil {
		return nil, errors.Wrap(err, "unable to search pages")
	}
	return issues, nil
}

// Safe for concurrent use.
func (app *MigratorApp) MigrateChildren(parent *jira.Issue) (err error) {
	var children []jira.Issue
	// If its an epic, migrate its issues and any of thier children
	if parent.Fields.Type.Name == "Epic" {
		children, err = app.QueryIssues(app.From, `"Epic Link" = `+parent.Key+` ORDER BY key`)
		if err != nil {
			return errors.Wrap(err, "unable to query epic children")
		}
	}
	if len(parent.Fields.Subtasks) > 0 {
		children, err = app.QueryIssues(app.From, `parent in ("`+parent.Key+`") ORDER BY key`)
		if err != nil {
			return errors.Wrap(err, "unable to query subtasks")
		}
	}

	// we can migrate each child concurrently
	var errg errgroup.Group

	for _, child := range children {
		child := child // avoid loop closure captures

		// Depends on the parent being migrated already
		app.Progress.MarkMigratedParent(child.Key, app.Progress.MigratedKey(parent.Key))

		errg.Go(func() error {
			_, err := app.MigrateIssue(&child)
			if err != nil {
				return errors.Wrap(err, "unable to migrate child")
			}
			if err := app.MigrateChildren(&child); err != nil {
				return errors.Wrap(err, "unable to migrate children's children")
			}
			return nil
		})
	}

	return errg.Wait()
}

func (app *MigratorApp) GetParent(issue *jira.Issue) (*jira.Issue, error) {
	var parentKey string
	if parent := issue.Fields.Parent; parent != nil {
		parentKey = parent.Key
	}
	if epicKey := epicKey(issue); epicKey != "" {
		parentKey = epicKey
	}
	if parentKey == "" {
		return nil, nil
	}

	parents, err := app.QueryIssues(app.From, `issue = `+parentKey)
	if err != nil {
		return nil, err
	}
	if len(parents) == 0 {
		return nil, nil
	}

	// there can only be one parent
	return &parents[0], nil
}

// func (app *MigratorApp) GetParentRoot(issue *jira.Issue) (*jira.Issue, error) {
// 	// If it's a subtask or has an epic, migrate its parent first.
// 	parent, err := app.GetParent(issue)
// 	if err != nil {
// 		errors.Wrap(err, "unable to get parent")
// 	}
// 	if parent != nil {
// 		return app.GetParentRoot(parent)
// 	}
// 	return issue, nil
// }

// Migrates every parent up to root, but doesn't bother with siblings or cousins
func (app *MigratorApp) MigrateParents(issue *jira.Issue) error {
	parent, err := app.GetParent(issue)
	if err != nil {
		errors.Wrap(err, "unable to get parent")
	}
	if parent != nil {
		if err := app.MigrateParents(parent); err != nil {
			return err
		}
		migratedParentKey, err := app.MigrateIssue(parent)
		if err != nil {
			return err
		}
		app.Progress.MarkMigratedParent(issue.Key, migratedParentKey)
	}
	return nil
}

// Ensures that we only migrate each issue once without having to implement fancy
// deduplication logic for this unit of work
var migrateIssueGroup singleflight.Group

func (app *MigratorApp) MigrateIssue(issue *jira.Issue) (string, error) {
	app.ApiLimiter.Wait(context.Background())

	key, err, _ := migrateIssueGroup.Do(issue.Key, func() (interface{}, error) {
		return app.migrateIssue(issue)
	})
	return key.(string), err
}

func (app *MigratorApp) migrateIssue(issue *jira.Issue) (key string, err error) {
	defer func() {
		if err == nil {
			app.Progress.MarkMigrated(issue.Key, key)
		}
	}()

	fmt.Println("Migrating", issue.Key, "...")

	// First, check to see if this issue has already been migrated, and skip if so.
	migratedIssues, err := app.QueryIssues(app.To, `issue in issuesWithRemoteLinksByGlobalId("`+issue.Key+`") ORDER BY key DESC`)
	if err != nil {
		return "", err
	}
	if len(migratedIssues) > 0 {
		fmt.Println(issue.Key, "already migrated "+issue.Key+". Skipping.")
		return migratedIssues[0].Key, nil
	}

	newIssue := jira.Issue{
		Fields: &jira.IssueFields{
			Project: jira.Project{
				Key: app.ProjectKey,
			},
			Type: jira.IssueType{
				Name: issue.Fields.Type.Name,
			},
			Summary:     issue.Fields.Summary,
			Description: issue.Fields.Description,
			// TODO: Match priorities
			Priority: issue.Fields.Priority,
			Labels:   issue.Fields.Labels,
		},
	}

	// This makes the transition from server to cloud MigratorAppear better
	if name := epicName(issue); name != "" {
		newIssue.Fields.Summary = name
		newIssue.Fields.Description = issue.Fields.Summary + "\n\n" + issue.Fields.Description
	}

	if sprint := issue.Fields.Sprint; sprint != nil {
		newIssue.Fields.Sprint = &jira.Sprint{
			Name: sprint.Name,
		}
	}

	if reporter := issue.Fields.Reporter; reporter != nil {
		cloudUser, ok := app.UserLookup[reporter.EmailAddress]
		if ok {
			newIssue.Fields.Reporter = &jira.User{AccountID: cloudUser.AccountID}
		}
	}

	if assignee := issue.Fields.Assignee; assignee != nil {
		cloudUser, ok := app.UserLookup[assignee.EmailAddress]
		if ok {
			newIssue.Fields.Assignee = &jira.User{AccountID: cloudUser.AccountID}
		}
	}

	if app.Progress.IsParentMigrated(issue.Key) {
		newIssue.Fields.Parent = &jira.Parent{
			Key: app.Progress.MigratedParentKey(issue.Key),
		}
	}

	migrated, resp, err := app.To.Issue.Create(&newIssue)
	if err != nil {
		dumpResponse(resp)
		return "", errors.Wrap(err, "Error creating issue")
	}

	errg := errgroup.Group{}

	errg.Go(func() error {
		if _, resp, err := app.To.Issue.AddRemoteLink(migrated.ID, &jira.RemoteLink{
			GlobalID: issue.Key,
			Application: &jira.RemoteLinkApplication{
				Type: "jira.etsycorp.com",
				Name: "Migrated Issue",
			},
			Object: &jira.RemoteLinkObject{
				URL:     "https://jira.etsycorp.com/browse/" + issue.Key,
				Title:   issue.Key,
				Summary: issue.Fields.Summary,
			},
		}); err != nil {
			dumpResponse(resp)
			return errors.Wrap(err, "Error creating remote link")
		}
		return nil
	})

	errg.Go(func() error {
		// Comments can't be set on create. They must be added later
		if issue.Fields.Comments != nil {
			for _, comment := range issue.Fields.Comments.Comments {
				if _, resp, err := app.To.Issue.AddComment(migrated.ID, &jira.Comment{
					Name: comment.Name,
					// It's impossible to set a different author than "self",
					// so just indicate who wrote this originally in the body of the comment.
					Body:       "On " + comment.Created + " " + comment.Author.EmailAddress + " wrote:\n\n" + comment.Body,
					Visibility: comment.Visibility,
				}); err != nil {
					dumpResponse(resp)
					return errors.Wrapf(err, "Error adding comment to %s", migrated.Key)
				}
			}
		}
		return nil
	})

	errg.Go(func() error {
		// Attachments can't be set on create, they must be downloaded and posted later
		for _, attachment := range issue.Fields.Attachments {
			req, _ := http.NewRequest("GET", attachment.Content, nil)
			resp, err := app.From.Do(req, nil)
			if err != nil {
				dumpResponse(resp)
				return errors.Wrapf(err, "Error fetching attachment %q from issue %s", attachment.Filename, issue.Key)
			}
			defer resp.Body.Close()
			if _, resp, err := app.To.Issue.PostAttachment(migrated.ID, resp.Body, attachment.Filename); err != nil {
				dumpResponse(resp)
				return errors.Wrapf(err, "Error posting attachment %q to issue %s", attachment.Filename, migrated.Key)
			}
		}
		return nil
	})

	errg.Go(func() error {
		// Transition the ticket to the correct status
		transitions, resp, err := app.To.Issue.GetTransitions(migrated.ID)
		if err != nil {
			dumpResponse(resp)
			return errors.Wrapf(err, "Error fetching transitions for %s", migrated.Key)
		}
		for _, transition := range transitions {
			if transition.To.Name == issue.Fields.Status.Name {
				if resp, err := app.To.Issue.DoTransition(migrated.ID, transition.ID); err != nil {
					dumpResponse(resp)
					return errors.Wrapf(err, "Error transitioning issue %s to %q", migrated.Key, transition.To.Name)
				}
			}
		}
		return nil
	})

	if err := errg.Wait(); err != nil {
		return "", errors.Wrapf(err, "Error migrating %s", issue.Key)
	}

	fmt.Println("Successfully migrated", issue.Key, "to", migrated.Key)

	return migrated.Key, nil
}

func epicKey(issue *jira.Issue) string {
	if field, ok := issue.Fields.Unknowns["customfield_10620"]; ok {
		if epicKey, ok := field.(string); ok {
			return epicKey
		}
	}
	return ""
}

func epicName(issue *jira.Issue) string {
	if field, ok := issue.Fields.Unknowns["customfield_10621"]; ok {
		if epicName, ok := field.(string); ok {
			return epicName
		}
	}
	return ""
}

func getUsers(cloud *jira.Client, projectKey string) ([]jira.User, error) {
	project, _, err := cloud.Project.Get(projectKey)
	if err != nil {
		return nil, errors.Wrapf(err, "Error retrieving project %s", projectKey)
	}

	var users []jira.User

	for role, resource := range project.Roles {
		req, err := http.NewRequest("GET", resource, nil)
		if err != nil {
			return nil, errors.Wrapf(err, "Error retrieving %s role from %s", role, resource)
		}
		var role jira.Role
		if _, err := cloud.Do(req, &role); err != nil {
			return nil, errors.Wrapf(err, "Error retrieving %s role from %s", role, resource)
		}
		for _, actor := range role.Actors {
			user, _, err := cloud.User.GetByAccountID(actor.ActorUser.AccountID)
			if err != nil {
				return nil, errors.Wrapf(err, "Error retrieving user %q", actor.DisplayName)
			}
			users = append(users, *user)
		}
	}
	return users, nil
}
