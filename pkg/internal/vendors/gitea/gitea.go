package gitea

import giteasdk "code.gitea.io/sdk/gitea"

// NotFoundError is the error message returned in response body by Gitea API for 404
const NotFoundError = "404 Not Found"

// Client is an interface to Gitea that allows us to test easier
type Client interface {
	AdminCreateOrg(string, giteasdk.CreateOrgOption) (*giteasdk.Organization, error)
	GetOrg(string) (*giteasdk.Organization, error)
	EditOrg(string, giteasdk.EditOrgOption) error
	GetUserInfo(string) (*giteasdk.User, error)
	AdminCreateRepo(string, giteasdk.CreateRepoOption) (*giteasdk.Repository, error)
	CreateOrgRepo(string, giteasdk.CreateRepoOption) (*giteasdk.Repository, error)
	MigrateRepo(giteasdk.MigrateRepoOption) (*giteasdk.Repository, error)
	GetRepo(string, string) (*giteasdk.Repository, error)
	DeleteRepo(string, string) error
	CreateDeployKey(string, string, giteasdk.CreateKeyOption) (*giteasdk.DeployKey, error)
	GetDeployKey(string, string, int64) (*giteasdk.DeployKey, error)
	ListDeployKeys(string, string) ([]*giteasdk.DeployKey, error)
	DeleteDeployKey(string, string, int64) error
}

// NewClient is a Client factory
type NewClient func(url, token string) Client

// FakeClient is a Gitea fake client to be used in testing
type FakeClient struct {
	URL, Token string

	AdminCreateOrgExpectedCalls  []func(string, giteasdk.CreateOrgOption) (*giteasdk.Organization, error)
	GetOrgExpectedCalls          []func(string) (*giteasdk.Organization, error)
	EditOrgExpectedCalls         []func(string, giteasdk.EditOrgOption) error
	GetUserInfoExpectedCalls     []func(string) (*giteasdk.User, error)
	AdminCreateRepoExpectedCalls []func(string, giteasdk.CreateRepoOption) (*giteasdk.Repository, error)
	CreateOrgRepoExpectedCalls   []func(string, giteasdk.CreateRepoOption) (*giteasdk.Repository, error)
	MigrateRepoExpectedCalls     []func(giteasdk.MigrateRepoOption) (*giteasdk.Repository, error)
	GetRepoExpectedCalls         []func(string, string) (*giteasdk.Repository, error)
	DeleteRepoExpectedCalls      []func(string, string) error
	CreateDeployKeyExpectedCalls []func(string, string, giteasdk.CreateKeyOption) (*giteasdk.DeployKey, error)
	GetDeployKeyExpectedCalls    []func(string, string, int64) (*giteasdk.DeployKey, error)
	ListDeployKeysExpectedCalls  []func(string, string) ([]*giteasdk.DeployKey, error)
	DeleteDeployKeyExpectedCalls []func(string, string, int64) error
}

// NewFakeClient returns a gitea client constructor
func NewFakeClient(url, token string) *FakeClient {
	return &FakeClient{URL: url, Token: token}
}

// GetRepo calls the next expected call in GetRepoExpectedCalls and pops it afterwards
func (g *FakeClient) GetRepo(owner string, reponame string) (*giteasdk.Repository, error) {
	if len(g.GetRepoExpectedCalls) == 0 {
		panic("There are no expected calls for GetRepo")
	}
	callable := g.GetRepoExpectedCalls[0]

	g.GetRepoExpectedCalls = g.GetRepoExpectedCalls[1:]

	return callable(owner, reponame)
}

// AdminCreateOrg calls the next expected call in AdminCreateOrgExpectedCalls and pops it afterwards
func (g *FakeClient) AdminCreateOrg(user string, options giteasdk.CreateOrgOption) (*giteasdk.Organization, error) {
	if len(g.AdminCreateOrgExpectedCalls) == 0 {
		panic("There are no expected calls for AdminCreateOrg")
	}
	callable := g.AdminCreateOrgExpectedCalls[0]

	g.AdminCreateOrgExpectedCalls = g.AdminCreateOrgExpectedCalls[1:]

	return callable(user, options)
}

// CreateOrgRepo calls the next expected call in CreateOrgRepoExpectedCalls and pops it afterwards
func (g *FakeClient) CreateOrgRepo(user string, options giteasdk.CreateRepoOption) (*giteasdk.Repository, error) {
	if len(g.CreateOrgRepoExpectedCalls) == 0 {
		panic("There are no expected calls for CreateOrgRepo")
	}
	callable := g.CreateOrgRepoExpectedCalls[0]

	g.CreateOrgRepoExpectedCalls = g.CreateOrgRepoExpectedCalls[1:]

	return callable(user, options)
}

// EditOrg calls the next expected call in EditOrgExpectedCalls and pops it afterwards
func (g *FakeClient) EditOrg(org string, options giteasdk.EditOrgOption) error {
	if len(g.EditOrgExpectedCalls) == 0 {
		panic("There are no expected calls for EditOrg")
	}
	callable := g.EditOrgExpectedCalls[0]

	g.EditOrgExpectedCalls = g.EditOrgExpectedCalls[1:]

	return callable(org, options)
}

// GetUserInfo calls the next expected call in GetUserInfoExpectedCalls and pops it afterwards
func (g *FakeClient) GetUserInfo(user string) (*giteasdk.User, error) {
	if len(g.GetUserInfoExpectedCalls) == 0 {
		panic("There are no expected calls for GetUserInfo")
	}
	callable := g.GetUserInfoExpectedCalls[0]

	g.GetUserInfoExpectedCalls = g.GetUserInfoExpectedCalls[1:]

	return callable(user)
}

// AdminCreateRepo calls the next expected call in AdminCreateRepoExpectedCalls and pops it afterwards
func (g *FakeClient) AdminCreateRepo(user string, options giteasdk.CreateRepoOption) (*giteasdk.Repository, error) {
	if len(g.AdminCreateRepoExpectedCalls) == 0 {
		panic("There are no expected calls for AdminCreateRepo")
	}
	callable := g.AdminCreateRepoExpectedCalls[0]

	g.AdminCreateRepoExpectedCalls = g.AdminCreateRepoExpectedCalls[1:]

	return callable(user, options)
}

// GetOrg calls the next expected call in GetOrgExpectedCalls and pops it afterwards
func (g *FakeClient) GetOrg(orgname string) (*giteasdk.Organization, error) {
	if len(g.GetOrgExpectedCalls) == 0 {
		panic("There are no expected calls for GetOrg")
	}
	callable := g.GetOrgExpectedCalls[0]

	g.GetOrgExpectedCalls = g.GetOrgExpectedCalls[1:]

	return callable(orgname)
}

// DeleteRepo calls the next expected call in DeleteRepoExpectedCalls and pops it afterwards
func (g *FakeClient) DeleteRepo(owner string, repo string) error {
	if len(g.DeleteRepoExpectedCalls) == 0 {
		panic("There are no expected calls for DeleteRepo")
	}
	callable := g.DeleteRepoExpectedCalls[0]

	g.DeleteRepoExpectedCalls = g.DeleteRepoExpectedCalls[1:]

	return callable(owner, repo)
}

// MigrateRepo calls the next expected call in MigrateRepoExpectedCalls and pops it afterwards
func (g *FakeClient) MigrateRepo(options giteasdk.MigrateRepoOption) (*giteasdk.Repository, error) {
	if len(g.MigrateRepoExpectedCalls) == 0 {
		panic("There are no expected calls for MigrateRepo")
	}
	callable := g.MigrateRepoExpectedCalls[0]

	g.MigrateRepoExpectedCalls = g.MigrateRepoExpectedCalls[1:]

	return callable(options)
}

// CreateDeployKey calls the next expected call in CreateDeployKeyExpectedCalls and pops it afterwards
func (g *FakeClient) CreateDeployKey(user string, repo string, options giteasdk.CreateKeyOption) (*giteasdk.DeployKey, error) {
	if len(g.CreateDeployKeyExpectedCalls) == 0 {
		panic("There are no expected calls for CreateDeployKey")
	}
	callable := g.CreateDeployKeyExpectedCalls[0]

	g.CreateDeployKeyExpectedCalls = g.CreateDeployKeyExpectedCalls[1:]

	return callable(user, repo, options)
}

// GetDeployKey calls the next expected call in GetDeployKeyExpectedCalls and pops it afterwards
func (g *FakeClient) GetDeployKey(user string, repo string, id int64) (*giteasdk.DeployKey, error) {
	if len(g.GetDeployKeyExpectedCalls) == 0 {
		panic("There are no expected calls for GetDeployKey")
	}
	callable := g.GetDeployKeyExpectedCalls[0]

	g.GetDeployKeyExpectedCalls = g.GetDeployKeyExpectedCalls[1:]

	return callable(user, repo, id)
}

// ListDeployKeys calls the next expected call in ListDeployKeysExpectedCalls and pops it afterwards
func (g *FakeClient) ListDeployKeys(user string, repo string) ([]*giteasdk.DeployKey, error) {
	if len(g.ListDeployKeysExpectedCalls) == 0 {
		panic("There are no expected calls for ListDeployKeys")
	}
	callable := g.ListDeployKeysExpectedCalls[0]

	g.ListDeployKeysExpectedCalls = g.ListDeployKeysExpectedCalls[1:]

	return callable(user, repo)
}

// DeleteDeployKey calls the next expected call in DeleteDeployKeyExpectedCalls and pops it afterwards
func (g *FakeClient) DeleteDeployKey(user string, repo string, id int64) error {
	if len(g.DeleteDeployKeyExpectedCalls) == 0 {
		panic("There are no expected calls for DeleteDeployKey")
	}
	callable := g.DeleteDeployKeyExpectedCalls[0]

	g.DeleteDeployKeyExpectedCalls = g.DeleteDeployKeyExpectedCalls[1:]

	return callable(user, repo, id)
}
