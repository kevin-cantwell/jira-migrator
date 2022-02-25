package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	jira "github.com/andygrunwald/go-jira"
	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v2"
)

var (
	configFile string
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.StringVar(&configFile, "config", "config.yaml", "The configuration file to use.")
	flag.StringVar(&configFile, "c", "config.yaml", "The configuration file to use.")
	flag.Usage = func() {
		fmt.Println(`Usage:
    jira-migrator OPTIONS COMMAND
Options:
    --config,-c                 The configuration file to use. (default "config.json")
Commands:
    migrate ISSUE_KEY           Migrate issue from server to cloud. Also migrates child issues.
    server users PROJECT_KEY    List server users. Helpful for setting user_mappings configs.
    cloud users PROJECT_KEY     List cloud user metadata. Helpful for setting the user_mappings config.
`)
	}
	flag.Parse()

	configFile, err := os.Open(configFile)
	if err != nil {
		panic(err)
	}

	var config Config
	if err := yaml.NewDecoder(configFile).Decode(&config); err != nil {
		panic(err)
	}

	serverAuth := jira.BasicAuthTransport{
		Username: config.Server.Username,
		Password: config.Server.Password,
	}
	server, err := jira.NewClient(serverAuth.Client(), "https://"+config.Server.Host)
	if err != nil {
		panic(err)
	}

	cloudAuth := jira.BasicAuthTransport{
		Username: config.Cloud.Email,
		Password: config.Cloud.ApiKey,
	}
	cloud, err := jira.NewClient(cloudAuth.Client(), "https://"+config.Cloud.Host)
	if err != nil {
		panic(err)
	}

	cloudUsers, resp, err := getCloudUsers(cloud, config.Cloud.ProjectKey)
	if err != nil {
		respErrExit(resp, err)
	}

	userLookup := map[string]jira.User{}
	for _, user := range cloudUsers {
		userLookup[user.EmailAddress] = user
	}

	app := App{
		Server:     server,
		Cloud:      cloud,
		Config:     config,
		UserLookup: userLookup,
	}

	switch cmd := flag.Arg(0); cmd {
	case "migrate":
		issueKey := flag.Arg(1)
		if resp, err := app.MigrateIssue("", issueKey); err != nil {
			respErrExit(resp, err)
		}
	default:
		log.Printf("Invalid command: %q\n", cmd)
		os.Exit(1)
	}
}

func respErrExit(resp *jira.Response, err error) {
	if resp != nil {
		io.Copy(log.Writer(), resp.Body)
		log.Print("\n")
	}
	panic(err)
}

type Config struct {
	Server struct {
		Host       string `yaml:"host"`
		Username   string `yaml:"username"`
		Password   string `yaml:"password"`
		ProjectKey string `yaml:"project_key"`
	} `yaml:"server"`
	Cloud struct {
		Host       string `yaml:"host"`
		Email      string `yaml:"email"`
		ApiKey     string `yaml:"api_key"`
		ProjectKey string `yaml:"project_key"`
	} `yaml:"cloud"`
	UserMappings   map[string]string `yaml:"user_mappings"`
	StatusMappings map[string]string `yaml:"status_mappings"`
}

type App struct {
	Server     *jira.Client
	Cloud      *jira.Client
	Config     Config
	UserLookup map[string]jira.User
}

func (app *App) MigrateIssue(parentKey, issueKey string) (*jira.Response, error) {
	oldIssue, resp, err := app.Server.Issue.Get(issueKey, &jira.GetQueryOptions{
		FieldsByKeys: true,
	})
	if err != nil {
		return resp, errors.Wrapf(err, "Error fetching issue %s", issueKey)
	}

	newIssue := jira.Issue{
		Fields: &jira.IssueFields{
			Project: jira.Project{
				Key: app.Config.Cloud.ProjectKey,
			},
			Type: jira.IssueType{
				Name: oldIssue.Fields.Type.Name,
			},
			Summary:     oldIssue.Fields.Summary,
			Description: oldIssue.Fields.Description,
		},
	}

	if parentKey != "" {
		newIssue.Fields.Parent = &jira.Parent{
			Key: parentKey,
		}
	}

	if reporter := oldIssue.Fields.Reporter; reporter != nil {
		cloudUser, ok := app.UserLookup[reporter.EmailAddress]
		if ok {
			newIssue.Fields.Reporter = &jira.User{AccountID: cloudUser.AccountID}
		}
	}

	if assignee := oldIssue.Fields.Assignee; assignee != nil {
		cloudUser, ok := app.UserLookup[assignee.EmailAddress]
		if ok {
			newIssue.Fields.Assignee = &jira.User{AccountID: cloudUser.AccountID}
		}
	}

	createdIssue, resp, err := app.Cloud.Issue.Create(&newIssue)
	if err != nil {
		return resp, errors.Wrapf(err, "Error creating issue from %s", issueKey)
	}

	// Comments can't be set on create. They must be added later
	for _, comment := range oldIssue.Fields.Comments.Comments {
		if _, resp, err = app.Cloud.Issue.AddComment(createdIssue.ID, &jira.Comment{
			Name: comment.Name,
			// It's impossible to set a different author than "self",
			// so just indicate who wrote this originally in the body of the comment.
			Body:       comment.Author.EmailAddress + " wrote:\n\n" + comment.Body,
			Visibility: comment.Visibility,
		}); err != nil {
			return resp, errors.Wrapf(err, "Error adding comment to %s", createdIssue.Key)
		}
	}

	transitions, resp, err := app.Cloud.Issue.GetTransitions(createdIssue.ID)
	if err != nil {
		return resp, errors.Wrapf(err, "Error fetching transitions for %s", createdIssue.Key)
	}
	for _, transition := range transitions {
		if transition.To.Name == oldIssue.Fields.Status.Name {
			if resp, err := app.Cloud.Issue.DoTransition(createdIssue.ID, transition.ID); err != nil {
				return resp, errors.Wrapf(err, "Error transitioning issue %s to %q", createdIssue.Key, transition.To.Name)
			}
		}
	}

	fmt.Println("Migrated:", oldIssue.Key)

	// TODO figure out how to discover epic children
	for _, subtask := range oldIssue.Fields.Subtasks {
		app.MigrateIssue(createdIssue.Key, subtask.Key)
	}

	return nil, nil
}

func getCloudUsers(cloud *jira.Client, projectKey string) ([]jira.User, *jira.Response, error) {
	project, resp, err := cloud.Project.Get(projectKey)
	if err != nil {
		return nil, resp, errors.Wrapf(err, "Error retrieving project %s", projectKey)
	}

	var users []jira.User

	for role, resource := range project.Roles {
		req, err := http.NewRequest("GET", resource, nil)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "Error retrieving %s role from %s", role, resource)
		}
		var role jira.Role
		resp, err := cloud.Do(req, &role)
		if err != nil {
			return nil, resp, errors.Wrapf(err, "Error retrieving %s role from %s", role, resource)
		}
		for _, actor := range role.Actors {
			user, resp, err := cloud.User.GetByAccountID(actor.ActorUser.AccountID)
			if err != nil {
				return nil, resp, errors.Wrapf(err, "Error retrieving user %q", actor.DisplayName)
			}
			users = append(users, *user)
		}
	}
	return users, nil, nil
}
