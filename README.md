# gitea-service-broker
Open Service Broker for Gitea

## Entities

### Service Request
```yaml
name: repo name
organization: # the gitea organization for which to create the repo
teams: # teams under which the repo should be placed
  - teamA
  - teamB
```

#### Service Response
```yaml
ssh_url: # the repo url for accessing it over ssh
```

### Binding Request
```yaml
repo_name: "org/repo"
read_only: false # create a read-only or read-write binding
```

### Binding Response
```yaml
id_rsa: # the ssh id_rsa key for accesing the repo
```
