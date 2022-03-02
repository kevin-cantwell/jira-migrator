# jira-migrator
A hacky tool for migrating issues from one server to another

#### Features
* It's fast. It will migrate issues concurrently. It's actually so fast it can overload the server, so migrated issues are limited to roughly 1 per 100ms (10 per second).
* You select the issues you wish to migrate by specifying a JQL statement.
* It is idempodent and can be re-run without creating dupes. However, if the tool fails in the middle of a migration, issue state is undefined.
* You may include child issues, if any, in the migration.
* If an issue has a parent, it will also be migrated, but siblings and cousins (ie: parent's children or parent's parent's children) will not.

#### Non-features
* It will not migrate sprints or boards
* It will not migrate children

# Usage
You'll need to do some prep on your target project before migrating:
1. Ensure that every issue's type you're migrating has a corresponding issue with the _exact same name_ in the target project.
2. Ensure that every issue's status you're migrating has a corresponding status with the _exact same name_ in the target project.
3. For best results, 

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
This command will create issues in the target server's project.
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