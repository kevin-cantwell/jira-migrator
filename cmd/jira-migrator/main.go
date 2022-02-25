package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

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
					app, err := NewApp(c.String("config"))
					if err != nil {
						return err
					}

					issues, err := app.QueryIssues(c.String("jql"))
					if err != nil {
						return err
					}

					// migrate issues in the order they were returned from the query
					for _, issue := range issues {
						fmt.Println(issue.Key)
						if _, err := app.MigrateIssue(&issue); err != nil {
							return err
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
	UserLookup map[string]jira.User
}

func NewApp(pathToConfig string) (*App, error) {
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
		UserLookup: userLookup,
	}, nil
}

func (app *App) QueryIssues(jql string) ([]jira.Issue, error) {
	var issues []jira.Issue
	if err := app.From.Issue.SearchPages(jql, &jira.SearchOptions{
		Expand: "names",
	}, func(issue jira.Issue) error {
		issues = append(issues, issue)
		return nil
	}); err != nil {
		return nil, err
	}
	return issues, nil
}

func (app *App) MigrateIssue(issue *jira.Issue) (*jira.Issue, error) {
	newIssue := jira.Issue{
		Fields: &jira.IssueFields{
			Project: jira.Project{
				Key: app.Config.To.ProjectKey,
			},
			Type: jira.IssueType{
				Name: issue.Fields.Type.Name,
			},
			Summary:     issue.Fields.Summary,
			Description: issue.Fields.Description,
		},
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

	createdIssue, resp, err := app.To.Issue.Create(&newIssue)
	if err != nil {
		dumpResponse(resp)
		return nil, errors.Wrap(err, "Error creating issue")
	}

	if _, resp, err := app.To.Issue.AddRemoteLink(createdIssue.ID, &jira.RemoteLink{
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
		return nil, errors.Wrap(err, "Error creating remote link")
	}

	// Comments can't be set on create. They must be added later
	if issue.Fields.Comments != nil {
		for _, comment := range issue.Fields.Comments.Comments {
			if _, resp, err := app.To.Issue.AddComment(createdIssue.ID, &jira.Comment{
				Name: comment.Name,
				// It's impossible to set a different author than "self",
				// so just indicate who wrote this originally in the body of the comment.
				Body:       comment.Author.EmailAddress + " wrote:\n\n" + comment.Body,
				Visibility: comment.Visibility,
			}); err != nil {
				dumpResponse(resp)
				return nil, errors.Wrapf(err, "Error adding comment to %s", createdIssue.Key)
			}
		}
	}

	// Attachments can't be set on create, they must be downloaded and posted later
	for _, attachment := range issue.Fields.Attachments {
		resp, err := http.Get(attachment.Content)
		if err != nil {
			dumpResponse(&jira.Response{Response: resp})
			return nil, errors.Wrapf(err, "Error fetching attachment %q from issue %s", attachment.Filename, issue.Key)
		}
		defer resp.Body.Close()
		if _, resp, err := app.To.Issue.PostAttachment(createdIssue.ID, resp.Body, attachment.Filename); err != nil {
			dumpResponse(resp)
			return nil, errors.Wrapf(err, "Error posting attachment %q to issue %s", attachment.Filename, createdIssue.Key)
		}
	}

	// Transition the ticket to the correct status
	transitions, resp, err := app.To.Issue.GetTransitions(createdIssue.ID)
	if err != nil {
		return nil, errors.Wrapf(err, "Error fetching transitions for %s", createdIssue.Key)
	}
	for _, transition := range transitions {
		if transition.To.Name == issue.Fields.Status.Name {
			if resp, err := app.To.Issue.DoTransition(createdIssue.ID, transition.ID); err != nil {
				dumpResponse(resp)
				return nil, errors.Wrapf(err, "Error transitioning issue %s to %q", createdIssue.Key, transition.To.Name)
			}
		}
	}

	// // Migrate all linked issues
	// for _, link := range issue.Fields.IssueLinks {
	// 	fmt.Printf("%+v\n", link)
	// 	// only link outwardly to avoid dupes
	// 	outward := link.OutwardIssue
	// 	if outward != nil && outward.Key != issue.Key {
	// 		outwardIssue, resp, err := app.Server.Issue.Get(outward.Key, &jira.GetQueryOptions{
	// 			FieldsByKeys: true,
	// 			Expand:       "names",
	// 		})
	// 		if err != nil {
	// 			return nil, errors.Wrapf(err, "Error fetching outward link %s", outward.Key)
	// 		}
	// 		createdOutwardIssue, resp, err := app.MigrateIssue(nil, outwardIssue)
	// 		if err != nil {
	// 			return nil, errors.Wrapf(err, "Error migrating outward link %s", outward.Key)
	// 		}
	// 		app.To.Issue.AddLink(&jira.IssueLink{
	// 			Type:         link.Type,
	// 			OutwardIssue: createdOutwardIssue,
	// 			InwardIssue:  createdIssue,
	// 			// Comment:      link.Comment, // Too annoying to deal with right now (my god jira is complex)
	// 		})
	// 	}
	// }

	// Migrate all subtasks
	// for _, subtask := range issue.Fields.Subtasks {
	// 	subIssue, resp, err := app.From.Issue.Get(subtask.Key, &jira.GetQueryOptions{
	// 		FieldsByKeys: true,
	// 		Expand:       "names",
	// 	})
	// 	if err != nil {
	// 		return nil, errors.Wrapf(err, "Error fetching subtask %s", subtask.Key)
	// 	}
	// 	if _, resp, err := app.MigrateIssue(createdIssue, subIssue); err != nil {
	// 		return nil, errors.Wrapf(err, "Error migrating subtask %s", subIssue.Key)
	// 	}
	// }

	// // Migrate all epic children
	// if issue.Fields.Type.Name == "Epic" {
	// 	issue.Fields.
	// }

	return createdIssue, nil
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
