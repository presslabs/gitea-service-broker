package broker

import "code.gitea.io/sdk/gitea"

// GiteaNotFoundError is the error message returned in response body by Gitea API for 404
const GiteaNotFoundError = "404 Not Found"

// GiteaClient is an interface to Gitea that allows us to test easier
type GiteaClient interface {
	AdminCreateOrg(string, gitea.CreateOrgOption) (*gitea.Organization, error)
	GetOrg(string) (*gitea.Organization, error)
	EditOrg(string, gitea.EditOrgOption) error
	GetUserInfo(string) (*gitea.User, error)
	AdminCreateRepo(string, gitea.CreateRepoOption) (*gitea.Repository, error)
	CreateOrgRepo(string, gitea.CreateRepoOption) (*gitea.Repository, error)
	MigrateRepo(gitea.MigrateRepoOption) (*gitea.Repository, error)
	GetRepo(string, string) (*gitea.Repository, error)
	DeleteRepo(string, string) error
	CreateDeployKey(string, string, gitea.CreateKeyOption) (*gitea.DeployKey, error)
	GetDeployKey(string, string, int64) (*gitea.DeployKey, error)
	DeleteDeployKey(string, string, int64) error
}

// NewGiteaClient is a GiteaClient factory
type NewGiteaClient func(url, token string) GiteaClient

// GiteaFakeClient is a Gitea fake client to be used in testing
type GiteaFakeClient struct {
	URL, Token string

	AdminCreateOrgExpectedCalls  []func(string, gitea.CreateOrgOption) (*gitea.Organization, error)
	GetOrgExpectedCalls          []func(string) (*gitea.Organization, error)
	EditOrgExpectedCalls         []func(string, gitea.EditOrgOption) error
	GetUserInfoExpectedCalls     []func(string) (*gitea.User, error)
	AdminCreateRepoExpectedCalls []func(string, gitea.CreateRepoOption) (*gitea.Repository, error)
	CreateOrgRepoExpectedCalls   []func(string, gitea.CreateRepoOption) (*gitea.Repository, error)
	MigrateRepoExpectedCalls     []func(gitea.MigrateRepoOption) (*gitea.Repository, error)
	GetRepoExpectedCalls         []func(string, string) (*gitea.Repository, error)
	DeleteRepoExpectedCalls      []func(string, string) error
	CreateDeployKeyExpectedCalls []func(string, string, gitea.CreateKeyOption) (*gitea.DeployKey, error)
	GetDeployKeyExpectedCalls    []func(string, string, int64) (*gitea.DeployKey, error)
	DeleteDeployKeyExpectedCalls []func(string, string, int64) error
}

// NewFakeGiteaClientFactory returns a gitea client constructor
func NewFakeGiteaClientFactory(fakeGiteaClient *GiteaFakeClient) NewGiteaClient {
	return func(url, token string) GiteaClient {
		fakeGiteaClient.URL = url
		fakeGiteaClient.Token = token
		return fakeGiteaClient
	}
}

// NewGiteaClientFactory returns a gitea client constructor
func NewGiteaClientFactory() NewGiteaClient {
	return func(url, token string) GiteaClient {
		return gitea.NewClient(url, token)
	}
}

// GetRepo calls the next expected call in GetRepoExpectedCalls and pops it afterwards
func (g *GiteaFakeClient) GetRepo(owner string, reponame string) (*gitea.Repository, error) {
	if len(g.GetRepoExpectedCalls) == 0 {
		panic("There are no expected calls for GetRepo")
	}
	callable := g.GetRepoExpectedCalls[0]

	g.GetRepoExpectedCalls = g.GetRepoExpectedCalls[1:]

	return callable(owner, reponame)
}

// AdminCreateOrg calls the next expected call in AdminCreateOrgExpectedCalls and pops it afterwards
func (g *GiteaFakeClient) AdminCreateOrg(user string, options gitea.CreateOrgOption) (*gitea.Organization, error) {
	if len(g.AdminCreateOrgExpectedCalls) == 0 {
		panic("There are no expected calls for AdminCreateOrg")
	}
	callable := g.AdminCreateOrgExpectedCalls[0]

	g.AdminCreateOrgExpectedCalls = g.AdminCreateOrgExpectedCalls[1:]

	return callable(user, options)
}

// CreateOrgRepo calls the next expected call in CreateOrgRepoExpectedCalls and pops it afterwards
func (g *GiteaFakeClient) CreateOrgRepo(user string, options gitea.CreateRepoOption) (*gitea.Repository, error) {
	if len(g.CreateOrgRepoExpectedCalls) == 0 {
		panic("There are no expected calls for CreateOrgRepo")
	}
	callable := g.CreateOrgRepoExpectedCalls[0]

	g.CreateOrgRepoExpectedCalls = g.CreateOrgRepoExpectedCalls[1:]

	return callable(user, options)
}

// EditOrg calls the next expected call in EditOrgExpectedCalls and pops it afterwards
func (g *GiteaFakeClient) EditOrg(org string, options gitea.EditOrgOption) error {
	if len(g.EditOrgExpectedCalls) == 0 {
		panic("There are no expected calls for EditOrg")
	}
	callable := g.EditOrgExpectedCalls[0]

	g.EditOrgExpectedCalls = g.EditOrgExpectedCalls[1:]

	return callable(org, options)
}

// GetUserInfo calls the next expected call in GetUserInfoExpectedCalls and pops it afterwards
func (g *GiteaFakeClient) GetUserInfo(user string) (*gitea.User, error) {
	if len(g.GetUserInfoExpectedCalls) == 0 {
		panic("There are no expected calls for GetUserInfo")
	}
	callable := g.GetUserInfoExpectedCalls[0]

	g.GetUserInfoExpectedCalls = g.GetUserInfoExpectedCalls[1:]

	return callable(user)
}

// AdminCreateRepo calls the next expected call in AdminCreateRepoExpectedCalls and pops it afterwards
func (g *GiteaFakeClient) AdminCreateRepo(user string, options gitea.CreateRepoOption) (*gitea.Repository, error) {
	if len(g.AdminCreateRepoExpectedCalls) == 0 {
		panic("There are no expected calls for CreateOrgRepo")
	}
	callable := g.AdminCreateRepoExpectedCalls[0]

	g.AdminCreateRepoExpectedCalls = g.AdminCreateRepoExpectedCalls[1:]

	return callable(user, options)
}

// GetOrg calls the next expected call in GetOrgExpectedCalls and pops it afterwards
func (g *GiteaFakeClient) GetOrg(orgname string) (*gitea.Organization, error) {
	if len(g.GetOrgExpectedCalls) == 0 {
		panic("There are no expected calls for GetOrg")
	}
	callable := g.GetOrgExpectedCalls[0]

	g.GetOrgExpectedCalls = g.GetOrgExpectedCalls[1:]

	return callable(orgname)
}

// DeleteRepo calls the next expected call in DeleteRepoExpectedCalls and pops it afterwards
func (g *GiteaFakeClient) DeleteRepo(owner string, repo string) error {
	if len(g.DeleteRepoExpectedCalls) == 0 {
		panic("There are no expected calls for EditOrg")
	}
	callable := g.DeleteRepoExpectedCalls[0]

	g.DeleteRepoExpectedCalls = g.DeleteRepoExpectedCalls[1:]

	return callable(owner, repo)
}

// MigrateRepo calls the next expected call in MigrateRepoExpectedCalls and pops it afterwards
func (g *GiteaFakeClient) MigrateRepo(options gitea.MigrateRepoOption) (*gitea.Repository, error) {
	if len(g.MigrateRepoExpectedCalls) == 0 {
		panic("There are no expected calls for MigrateRepo")
	}
	callable := g.MigrateRepoExpectedCalls[0]

	g.MigrateRepoExpectedCalls = g.MigrateRepoExpectedCalls[1:]

	return callable(options)
}

// CreateDeployKey calls the next expected call in CreateDeployKeyExpectedCalls and pops it afterwards
func (g *GiteaFakeClient) CreateDeployKey(user string, repo string, options gitea.CreateKeyOption) (*gitea.DeployKey, error) {
	if len(g.CreateDeployKeyExpectedCalls) == 0 {
		panic("There are no expected calls for CreateDeployKey")
	}
	callable := g.CreateDeployKeyExpectedCalls[0]

	g.CreateDeployKeyExpectedCalls = g.CreateDeployKeyExpectedCalls[1:]

	return callable(user, repo, options)
}

// GetDeployKey calls the next expected call in GetDeployKeyExpectedCalls and pops it afterwards
func (g *GiteaFakeClient) GetDeployKey(user string, repo string, id int64) (*gitea.DeployKey, error) {
	if len(g.GetDeployKeyExpectedCalls) == 0 {
		panic("There are no expected calls for CreateDeployKey")
	}
	callable := g.GetDeployKeyExpectedCalls[0]

	g.GetDeployKeyExpectedCalls = g.GetDeployKeyExpectedCalls[1:]

	return callable(user, repo, id)
}

// DeleteDeployKey calls the next expected call in DeleteDeployKeyExpectedCalls and pops it afterwards
func (g *GiteaFakeClient) DeleteDeployKey(user string, repo string, id int64) error {
	if len(g.DeleteDeployKeyExpectedCalls) == 0 {
		panic("There are no expected calls for DeleteDeployKey")
	}
	callable := g.DeleteDeployKeyExpectedCalls[0]

	g.DeleteDeployKeyExpectedCalls = g.DeleteDeployKeyExpectedCalls[1:]

	return callable(user, repo, id)
}
