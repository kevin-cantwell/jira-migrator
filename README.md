# jira-migrator
A hacky tool for migrating issues from Jira Server to Jira Cloud.

#### Features
* You select the issues you wish to migrate by specifying a JQL statement.
* It will migrate issues concurrently. It's so fast it can overload the server, so a rate limit option can be set. The default is 7 api requests per server per second (about 2-3 issues per second), which seems to be about the upper bound before you start to see exponential backoffs.
* It is somwewhat idempodent in that it can be re-run without creating dupes. However, if the tool fails in the middle of a migration, migrated issues may be incomplete.
* You may optionally migrate child issues.
* If an issue is a subtask or has an epic, its parent will also be migrated to maintain issue heirarchy. Siblings and cousins (ie: parent's children or parent's parent's children) will not, unless they also appear in the JQL results.
* "Backlinks" to the original Jira Server issue will appear in the migrated issue as a remote link.

#### Non-features
* Sprints or boards cannot be migrated
* Issue links are not migrated

#### Known issues
* Priority does not migrate: https://github.com/kevin-cantwell/jira-migrator/issues/1

# Installation
You can grab a binary from the [releases page](https://github.com/kevin-cantwell/jira-migrator/releases).

# Usage

### Inspecting issues
This command is read-only and can do no harm.

```
NAME:
   jira-migrator inspect - Inspect issues

USAGE:
   jira-migrator inspect [command options] [arguments...]

OPTIONS:
   --host value  The host to query. Valid values are "server" and "cloud" (default: "server")
   --jql value   The JQL query string to execute against the configured "server" server.
   --help, -h    show help (default: false)
```

### Migrating issues
You'll need to do some prep on your target project before migrating:
1. Ensure that, for every issue you're migrating, its type has a corresponding issue with the _*exact same name*_ in the cloud project.
2. Ensure that, for every issue you're migrating, its status has a corresponding status with the _*exact same name*_ in the cloud project.
3. For best results, add as many users that appear in the issues you're migrating as members of your cloud project as well. The tool will make a best effort to match them by email address. Any misses will be replaced by your cloud user.
4. TURN OFF ALL NOTIFICATIONS for each user in the cloud project before migrating. Your project members will thank you.

```
NAME:
   jira-migrator migrate - Migrate issues server one server to another

USAGE:
   jira-migrator migrate [command options] PROJECT_KEY

OPTIONS:
   --jql value         The JQL query string to execute against the configured "server" server.
   --children          Set if you want to migrate all child issues. (default: false)
   --rate-limit value  Set the api rate limit (max requests per second) to respect. (default: 7)
   --help, -h          show help (default: false)
```