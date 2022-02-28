package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"

	jira "github.com/andygrunwald/go-jira"
	cli "github.com/urfave/cli/v2"
	yaml "gopkg.in/yaml.v2"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	cliApp := &cli.App{
		Name:  "jira-migrator",
		Usage: "migrate tickets from one server to another",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Value:   "config.yaml",
				Usage:   "The configuration file to use.",
			},
			&cli.BoolFlag{
				Name:  "dryrun",
				Usage: "Run through all the migration steps without creating anything on the \"to\" server.",
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "migrate",
				Usage: "Migrate issues from one server to another",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "jql",
						Usage:    "The JQL query string to execute against the configured \"from\" server.",
						Required: true,
					},
				},
				Action: func(c *cli.Context) error {
					c.String("config")
					app, err := NewApp(c.String("config"), c.Bool("dryrun"))
					if err != nil {
						return errors.Wrap(err, "unable to configure app")
					}

					meta, _, err := app.From.Issue.GetCreateMeta(app.Config.From.ProjectKey)
					for _, p := range meta.Projects {
						for _, it := range p.IssueTypes {
							if it.Name == "Epic" {

							}
						}
					}

					issues, err := app.QueryIssues(app.From, c.String("jql"))
					if err != nil {
						return errors.Wrap(err, "unable to query issues")
					}

					// migrate issues in the order they were returned from the query
					for _, issue := range issues {
						// b, _ := json.Marshal(issue.Fields.Unknowns)
						// panic(string(b))
						if _, err := app.MigrateIssue(&issue); err != nil {
							return errors.Wrap(err, "unable to migrate issue")
						}
					}

					return nil
				},
			},
		},
	}

	err := cliApp.Run(os.Args)
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
		io.Copy(os.Stderr, resp.Body)
		fmt.Fprint(os.Stderr, "\n")
	}
}

type Config struct {
	From struct {
		Host       string `yaml:"host"`
		Username   string `yaml:"username"`
		Password   string `yaml:"password"`
		ProjectKey string `yaml:"project_key"`
	} `yaml:"from"`
	To struct {
		Host       string `yaml:"host"`
		Username   string `yaml:"username"`
		Password   string `yaml:"password"`
		ProjectKey string `yaml:"project_key"`
	} `yaml:"to"`
	// UserMappings   map[string]string `yaml:"user_mappings"`
	// StatusMappings map[string]string `yaml:"status_mappings"`
}

type App struct {
	From       *jira.Client
	To         *jira.Client
	Config     Config
	DryRun     bool
	UserLookup map[string]jira.User
}

func NewApp(pathToConfig string, dryrun bool) (*App, error) {
	configFile, err := os.Open(pathToConfig)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.NewDecoder(configFile).Decode(&config); err != nil {
		return nil, err
	}

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

	toUsers, err := getUsers(to, config.To.ProjectKey)
	if err != nil {
		return nil, err
	}

	userLookup := map[string]jira.User{}
	for _, user := range toUsers {
		userLookup[user.EmailAddress] = user
	}

	return &App{
		From:       from,
		To:         to,
		Config:     config,
		DryRun:     dryrun,
		UserLookup: userLookup,
	}, nil
}

func (app *App) QueryIssues(client *jira.Client, jql string) ([]jira.Issue, error) {
	var issues []jira.Issue
	if err := client.Issue.SearchPages(jql, &jira.SearchOptions{
		Expand: "names",
		Fields: []string{
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
			"customfield_10620", // epic
		},
	}, func(issue jira.Issue) error {
		issues = append(issues, issue)
		return nil
	}); err != nil {
		return nil, errors.Wrap(err, "unable to search pages")
	}
	return issues, nil
}

/*
	Attempts to recursively migrate an issue's entire family tree.
	The family tree of each parent, epic, and subtask will also be migrated.
	An attempt is made to migrate keys in the same order in which they appear in
	the "from" server (ie: earliest keys get migrated first)
*/
func (app *App) MigrateFamilyTree(issue *jira.Issue) error {
	// recursively travel up the family tree and migrate all parents
	parent, err := app.GetParent(issue)
	if err != nil {
		return errors.Wrap(err, "unable to get parent")
	}
	if parent != nil {
		// migrating the parent's family tree will also result in `issue`
		// being migrated, so we can return here
		return app.MigrateFamilyTree(parent)
	}

	// If no parents, migrate the issue and any children it may have

	migratedKey, err := app.MigrateIssue(issue)
	if err != nil {
		return errors.Wrap(err, "unable to migrate issue")
	}

	opts := &MigrateOptions{}
	if issue.Fields.Type.Name == "Epic" {
		opts.MigratedEpicKey = migratedKey
	} else {
		opts.MigratedParentKey = migratedKey
	}

	return app.MigrateChildren(issue, opts)
}

func (app *App) MigrateChildren(parent *jira.Issue, opts *MigrateOptions) error {
	// If its an epic, migrate its issues and any of thier children
	if parent.Fields.Type.Name == "Epic" {
		children, err := app.QueryIssues(app.From, `"Epic Link" = `+parent.Key+` ORDER BY key`)
		if err != nil {
			return errors.Wrap(err, "unable to query epic children")
		}
		for _, child := range children {
			migratedKey, err := app.MigrateIssue(&child)
			if err != nil {
				return errors.Wrap(err, "unable to migrate child")
			}
			child.Fields.Parent = &jira.Parent{
				Key: opts.MigratedEpicKey,
			}
			if _, _, err := app.To.Issue.Update(&child); err != nil {
				return errors.Wrap(err, "unable to link epic")
			}
			if err := app.MigrateChildren(&child, &MigrateOptions{
				MigratedEpicKey: migratedKey,
			}); err != nil {
				return errors.Wrap(err, "unable to migrate children's children")
			}
		}
		return nil
	}

	// If it has subtasks, migrate them
	if len(parent.Fields.Subtasks) > 0 {
		children, err := app.QueryIssues(app.From, `parent in ("`+parent.Key+`") ORDER BY key`)
		if err != nil {
			return errors.Wrap(err, "unable to query subtasks")
		}
		for _, child := range children {
			if _, err := app.MigrateIssue(&child); err != nil {
				return errors.Wrap(err, "unable to migrate subtask")
			}
			child.Fields.Parent = &jira.Parent{
				Key: opts.MigratedParentKey,
			}
			if _, _, err := app.To.Issue.Update(&child); err != nil {
				return errors.Wrap(err, "unable to link pages")
			}
		}
	}

	return nil
}

func (app *App) GetParent(issue *jira.Issue) (*jira.Issue, error) {
	var parentKey string
	if parent := issue.Fields.Parent; parent != nil {
		parentKey = parent.Key
	}
	if epicKey := epicLink(issue); epicKey != "" {
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

type MigrateOptions struct {
	MigratedParentKey string
	MigratedEpicKey   string
}

func (app *App) MigrateIssue(issue *jira.Issue) (string, error) {
	// First, check to see if this issue has already been migrated, and skip if so.
	migrated, err := app.QueryIssues(app.To, `issue in issuesWithRemoteLinksByGlobalId("`+issue.Key+`") ORDER BY key DESC`)
	if err != nil {
		return "", err
	}
	if len(migrated) > 0 {
		fmt.Println(issue.Key, "already migrated at", time.Time(migrated[0].Fields.Created).Format("2006-01-02 15:04")+". Skipping.")
		// return migrated[0].Key, nil
	}

	fmt.Println("Migrating", issue.Key, "...")

	// TODO: Match priorities

	newIssue := jira.Issue{
		Fields: &jira.IssueFields{
			Project: jira.Project{
				Key: app.Config.To.ProjectKey,
			},
			Type: jira.IssueType{
				Name:    issue.Fields.Type.Name,
				Subtask: issue.Fields.Type.Subtask,
			},
			Summary:     issue.Fields.Summary,
			Description: issue.Fields.Description,
			Priority:    issue.Fields.Priority,
			Labels:      issue.Fields.Labels,
		},
	}

	// If it's a subtask or has an epic, migrate its parent first.
	parent, err := app.GetParent(issue)
	if err != nil {
		return "", errors.Wrap(err, "unable to fetch parent")
	}
	if parent != nil {
		migratedParentKey, err := app.MigrateIssue(parent)
		if err != nil {
			return "", errors.Wrap(err, "unable to migrate issue")
		}
		newIssue.Fields.Parent = &jira.Parent{
			Key: migratedParentKey,
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

	if app.DryRun {
		fmt.Println("Successfully migrated", issue.Key, "to", "DRYRUN-1")
		return "DRYRUN-1", nil
	}

	createdIssue, resp, err := app.To.Issue.Create(&newIssue)
	if err != nil {
		dumpResponse(resp)
		return "", errors.Wrap(err, "Error creating issue")
	}

	if _, resp, err := app.To.Issue.AddRemoteLink(createdIssue.ID, &jira.RemoteLink{
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
		return "", errors.Wrap(err, "Error creating remote link")
	}

	// Comments can't be set on create. They must be added later
	if issue.Fields.Comments != nil {
		for _, comment := range issue.Fields.Comments.Comments {
			if _, resp, err := app.To.Issue.AddComment(createdIssue.ID, &jira.Comment{
				Name: comment.Name,
				// It's impossible to set a different author than "self",
				// so just indicate who wrote this originally in the body of the comment.
				Body:       "On " + comment.Created + " " + comment.Author.EmailAddress + " wrote:\n\n" + comment.Body,
				Visibility: comment.Visibility,
			}); err != nil {
				dumpResponse(resp)
				return "", errors.Wrapf(err, "Error adding comment to %s", createdIssue.Key)
			}
		}
	}

	// Attachments can't be set on create, they must be downloaded and posted later
	for _, attachment := range issue.Fields.Attachments {
		req, _ := http.NewRequest("GET", attachment.Content, nil)
		resp, err := app.From.Do(req, nil)
		if err != nil {
			dumpResponse(resp)
			return "", errors.Wrapf(err, "Error fetching attachment %q from issue %s", attachment.Filename, issue.Key)
		}
		defer resp.Body.Close()
		if _, resp, err := app.To.Issue.PostAttachment(createdIssue.ID, resp.Body, attachment.Filename); err != nil {
			dumpResponse(resp)
			return "", errors.Wrapf(err, "Error posting attachment %q to issue %s", attachment.Filename, createdIssue.Key)
		}
	}

	// Transition the ticket to the correct status
	transitions, resp, err := app.To.Issue.GetTransitions(createdIssue.ID)
	if err != nil {
		return "", errors.Wrapf(err, "Error fetching transitions for %s", createdIssue.Key)
	}
	for _, transition := range transitions {
		if transition.To.Name == issue.Fields.Status.Name {
			if resp, err := app.To.Issue.DoTransition(createdIssue.ID, transition.ID); err != nil {
				dumpResponse(resp)
				return "", errors.Wrapf(err, "Error transitioning issue %s to %q", createdIssue.Key, transition.To.Name)
			}
		}
	}

	fmt.Println("Successfully migrated", issue.Key, "to", createdIssue.Key)

	return createdIssue.Key, nil
}

func epicLink(issue *jira.Issue) string {
	if field, ok := issue.Fields.Unknowns["customfield_10620"]; ok {
		if epicKey, ok := field.(string); ok {
			return epicKey
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

func (app *App) BuildTree(issue *jira.Issue) error {
	parent, err := app.GetParent(issue)
	if err != nil {
		return err
	}
	panic(parent)
}

var tree map[string]*Node

type Node struct {
	Issue    *jira.Issue
	Parent   *jira.Issue
	Chidren  []jira.Issue
	Migrated *jira.Issue
}

type Issue struct {
	Expand         string                    `json:"expand,omitempty" structs:"expand,omitempty"`
	ID             string                    `json:"id,omitempty" structs:"id,omitempty"`
	Self           string                    `json:"self,omitempty" structs:"self,omitempty"`
	Key            string                    `json:"key,omitempty" structs:"key,omitempty"`
	Fields         json.RawMessage           `json:"fields,omitempty" structs:"fields,omitempty"`
	RenderedFields *jira.IssueRenderedFields `json:"renderedFields,omitempty" structs:"renderedFields,omitempty"`
	Changelog      *jira.Changelog           `json:"changelog,omitempty" structs:"changelog,omitempty"`
	Transitions    []jira.Transition         `json:"transitions,omitempty" structs:"transitions,omitempty"`
	Names          map[string]string         `json:"names,omitempty" structs:"names,omitempty"`
}
