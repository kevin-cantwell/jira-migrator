package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	jira "github.com/andygrunwald/go-jira"
)

var (
	configFile string
)

func main() {
	flag.StringVar(&configFile, "config", "config.json", "The configuration file to use.")
	flag.StringVar(&configFile, "c", "config.json", "The configuration file to use.")

	configFile, err := os.Open(configFile)
	if err != nil {
		panic(err)
	}
	var config Config
	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		panic(err)
	}

	server, err := jira.NewClient(nil, "https://"+config.Server.Host)
	if err != nil {
		panic(err)
	}
	server.Authentication.SetBasicAuth(config.Server.Username, config.Server.Password)

	cloud, err := jira.NewClient(nil, "https://"+config.Cloud.Host)
	if err != nil {
		panic(err)
	}
	cloud.Authentication.SetBasicAuth(config.Cloud.Email, config.Cloud.ApiKey)

	clients := Clients{
		Server: server,
		Cloud:  cloud,
		Config: config,
	}

	fmt.Println(clients.Config)
}

type Clients struct {
	Server *jira.Client
	Cloud  *jira.Client
	Config Config
}

type Config struct {
	Server struct {
		Host     string `json:"host"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"server"`
	Cloud struct {
		Host   string `json:"host"`
		Email  string `json:"email"`
		ApiKey string `json:"api_key"`
	} `json:"cloud"`
}
