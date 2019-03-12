package broker

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	giteasdk "code.gitea.io/sdk/gitea"
)

var (
	repo = &giteasdk.Repository{
		Name: "test-repo",
		Owner: &giteasdk.User{
			UserName: "presslabs",
			ID:       1234,
		},
		HTMLURL: "git.presslabs.net/presslabs/test",
	}
	deployKey = &giteasdk.DeployKey{
		ID:          1234,
		KeyID:       1234,
		Title:       "test",
		Key:         publicKey,
		Fingerprint: publicKeyFingerprint,
	}
	// public openssh rsa key
	publicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCGz7M6TyB/W6Izqu5tBea1DxTnzZ" +
		"qlQfL25+pkIM/PtHGYDZQov6gBkp4ZCFBC0/dWkBY1Q3SEEyPKzXa2buK+lHqkI2ixk+reafcf" +
		"0OmguS6MiU+Qz60jTJEl9uxlg9uD7SG1CgAZh4BB9TwBfrPkqM05+8DrS5+MvpZgN0Eogw=="
	// fingerprint of above public key as given by Gitea
	publicKeyFingerprint = "SHA256:rDNaCPwonVCokZeaK7R8eVmI2dzhiqW87zLs8yuYsNQ"
)

func listDeployKeysCall(user string, repoName string) ([]*giteasdk.DeployKey, error) {
	defer GinkgoRecover()
	Expect(user).To(Equal(repo.Owner.UserName))
	Expect(repoName).To(Equal(repo.Name))

	return []*giteasdk.DeployKey{
		{
			Fingerprint: "finger",
		},
		deployKey,
		{
			Fingerprint: "print",
		},
	}, nil
}

func listDeployKeysNotFoundCall(user string, repoName string) ([]*giteasdk.DeployKey, error) {
	defer GinkgoRecover()
	Expect(user).To(Equal(repo.Owner.UserName))
	Expect(repoName).To(Equal(repo.Name))

	return []*giteasdk.DeployKey{
		{
			ID:          1234,
			KeyID:       1234,
			Title:       "a different title",
			Fingerprint: publicKeyFingerprint,
		},
	}, nil
}

func getRepoCall(owner string, name string) (*giteasdk.Repository, error) {
	defer GinkgoRecover()
	Expect(owner).To(Equal(repo.Owner.UserName))
	Expect(name).To(Equal(repo.Name))

	return repo, nil
}
