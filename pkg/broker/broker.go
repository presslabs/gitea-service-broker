package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	giteasdk "code.gitea.io/sdk/gitea"
	"github.com/google/uuid"
	"github.com/pivotal-cf/brokerapi"
	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/presslabs/gitea-service-broker/pkg/cmd/options"
	"github.com/presslabs/gitea-service-broker/pkg/internal/vendors/gitea"
)

type Binding struct {
	HostURL   string
	CloneURL  string
	PublicKey string
}

type ProvisionParameters struct {
	RepositoryName  string `json:"repository_name"`
	RepositoryOwner string `json:"repository_owner"`
	MigrateURL      string `json:"migrate_url,omitempty"`
}

type BindingParameters struct {
	Title     string `json:"title"`
	PublicKey string `json:"public_key"`
}

type GiteaServiceBroker struct {
	client.Client
	GiteaClient gitea.Client
}

var (
	ErrNotImplemented = brokerapi.NewFailureResponse(errors.New("not implemented"), http.StatusNotImplemented,
		"not-implemented")
	ErrInstanceNotFound = brokerapi.NewFailureResponseBuilder(
		errors.New("instance cannot be fetched"), http.StatusNotFound, "instance-not-found",
	).Build()
)

func (b *GiteaServiceBroker) Provision(ctx context.Context, instanceID string, provisionDetails brokerapi.ProvisionDetails,
	asyncAllowed bool) (spec brokerapi.ProvisionedServiceSpec, err error) {
	log.Info("provisioning instance")

	// Get the provision parameters
	parameters := ProvisionParameters{}
	err = json.Unmarshal(provisionDetails.GetRawParameters(), &parameters)
	if err != nil {
		return spec, err
	}

	// Validate the provision parameters
	errorList := []error{}

	if parameters.RepositoryName == "" {
		errorList = append(errorList, errors.New("`repository_name` must be specified"))
	}

	if parameters.RepositoryOwner == "" {
		errorList = append(errorList, errors.New("you must specify a `repository_owner`"))
	}

	err = utilerrors.Flatten(utilerrors.NewAggregate(errorList))
	if err != nil {
		return spec, brokerapi.NewFailureResponse(err, http.StatusBadRequest, "bad-request")
	}

	// Create the repository
	repository, err := b.provisionInstance(ctx, instanceID, parameters)
	if err != nil {
		return spec, err
	}

	spec.IsAsync = false
	spec.DashboardURL = repository.HTMLURL

	return spec, nil
}

func (b *GiteaServiceBroker) GetInstance(ctx context.Context, instanceID string) (brokerapi.GetInstanceDetailsSpec, error) {
	spec := brokerapi.GetInstanceDetailsSpec{}

	repository, err := b.getInstance(ctx, instanceID)
	if err != nil {
		return spec, err
	}

	spec.DashboardURL = repository.HTMLURL
	spec.PlanID = options.DefaultPlanID
	spec.ServiceID = options.ServiceID

	return spec, nil
}

func (b *GiteaServiceBroker) Deprovision(ctx context.Context, instanceID string, details brokerapi.DeprovisionDetails, asyncAllowed bool) (
	brokerapi.DeprovisionServiceSpec, error) {
	spec := brokerapi.DeprovisionServiceSpec{IsAsync: false}

	secret, err := b.getInstanceSecret(ctx, instanceID)
	if err != nil {
		if err == ErrInstanceNotFound {
			return spec, brokerapi.ErrInstanceDoesNotExist
		}
		return spec, err
	}

	owner, name, err := getRepositoryIdentity(secret)
	if err != nil {
		return spec, errors.New("couldn't deprovision instance")
	}

	err = b.GiteaClient.DeleteRepo(owner, name)
	if err != nil {
		if err.Error() != gitea.NotFoundError {
			// if the repo is not already deleted, return error
			return spec, errors.New("couldn't deprovision instance")
		}
		if time.Now().UTC().Sub(secret.GetCreationTimestamp().Time).Seconds() < options.OperationTimeout {
			return spec, brokerapi.ErrConcurrentInstanceAccess
		}
	}

	err = b.Client.Delete(ctx, secret)
	if err != nil {
		return spec, errors.New("couldn't deprovision instance")
	}

	return spec, nil
}

func (b *GiteaServiceBroker) Bind(ctx context.Context, instanceID, bindingID string, details brokerapi.BindDetails,
	asyncAllowed bool) (brokerapi.Binding, error) {
	binding := brokerapi.Binding{}

	instanceSecret, err := b.getInstanceSecret(ctx, instanceID)
	if err != nil {
		return binding, err
	}

	_, _, err = getRepositoryIdentity(instanceSecret)
	if err != nil {
		return binding, ErrInstanceNotFound
	}

	// get and validate the binding parameters
	parameters := BindingParameters{}
	err = json.Unmarshal(details.GetRawParameters(), &parameters)
	if err != nil {
		return binding, err
	}
	if parameters.Title == "" {
		title, err := uuid.NewRandom()
		if err != nil {
			log.Error(err, "couldn't generate a deploy key title")
			return binding, errors.New("couldn't generate a title")
		}

		parameters.Title = title.String()
	}
	var privateRSAKeyPEM string

	// create a OpenSSH RSA key pair
	if parameters.PublicKey == "" {
		privateRSAKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return binding, err
		}
		privateRSAKeyDer := x509.MarshalPKCS1PrivateKey(privateRSAKey)
		privateRSAKeyBlock := pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateRSAKeyDer,
		}
		privateRSAKeyPEM = string(pem.EncodeToMemory(&privateRSAKeyBlock))

		publicRSAKey := privateRSAKey.PublicKey
		publicKey, err := ssh.NewPublicKey(&publicRSAKey)
		if err != nil {
			return binding, err
		}
		publicKeyOpenSSH := fmt.Sprintf("%s %s",
			publicKey.Type(),
			base64.StdEncoding.EncodeToString(publicKey.Marshal()),
		)
		parameters.PublicKey = publicKeyOpenSSH

		if err != nil {
			return binding, err
		}
	}

	_, err = b.getOrCreateBinding(ctx, instanceID, bindingID, instanceSecret, parameters)
	if err != nil {
		return binding, err
	}

	credentials := map[string]string{
		"public_key": parameters.PublicKey,
	}
	if privateRSAKeyPEM != "" {
		credentials["private_key"] = privateRSAKeyPEM
	}
	binding.Credentials = credentials

	return binding, nil
}

// GetBinding returns a Gitea DeployKey info
func (b *GiteaServiceBroker) GetBinding(ctx context.Context, instanceID, bindingID string) (brokerapi.GetBindingSpec, error) {
	spec := brokerapi.GetBindingSpec{}

	instanceSecret, err := b.getInstanceSecret(ctx, instanceID)
	if err != nil {
		return spec, err
	}

	bindingSecret, err := b.getBindingSecret(ctx, bindingID)
	if err != nil {
		return spec, err
	}

	if err = b.validateBindingInstanceRelationship(instanceSecret, bindingSecret); err != nil {
		return spec, err
	}

	key, err := b._getDeployKey(ctx, instanceSecret, bindingSecret)
	if err != nil {
		if err == brokerapi.ErrBindingNotFound {
			return spec, err
		}
		if err == brokerapi.ErrBindingAlreadyExists {
			return spec, brokerapi.ErrBindingNotFound
		}
		return spec, errors.New("couldn't get existing binding")
	}

	spec.Credentials = map[string]string{
		"public_key": key.Key,
	}
	spec.Parameters = map[string]string{
		"title": key.Title,
	}

	return spec, nil
}

// Unbind deletes a Gitea DeployKey
func (b *GiteaServiceBroker) Unbind(ctx context.Context, instanceID, bindingID string, details brokerapi.UnbindDetails, asyncAllowed bool) (brokerapi.UnbindSpec, error) {
	spec := brokerapi.UnbindSpec{}

	instanceSecret, err := b.getInstanceSecret(ctx, instanceID)
	if err != nil {
		if err == ErrInstanceNotFound {
			return spec, brokerapi.ErrBindingNotFound
		}
		return spec, err
	}

	bindingSecret, err := b.getBindingSecret(ctx, bindingID)
	if err != nil {
		if err == brokerapi.ErrBindingNotFound {
			return spec, brokerapi.ErrBindingDoesNotExist
		}
		return spec, err
	}

	if err = b.validateBindingInstanceRelationship(instanceSecret, bindingSecret); err != nil {
		return spec, err
	}

	shouldDeleteKey := true
	key, err := b._getDeployKey(ctx, instanceSecret, bindingSecret)
	if err != nil {
		// If the binding was not found or was different
		if err == ErrInstanceNotFound ||
			err == brokerapi.ErrBindingNotFound ||
			err == brokerapi.ErrBindingAlreadyExists {
			shouldDeleteKey = false
		} else {
			if time.Now().UTC().Sub(bindingSecret.GetCreationTimestamp().Time).Seconds() < options.OperationTimeout {
				return spec, brokerapi.ErrConcurrentInstanceAccess
			}
			return spec, errors.New("couldn't deprovision instance")
		}
	}

	if shouldDeleteKey {
		owner, repoName, _, _, err := getDeployKeyIdentity(instanceSecret, bindingSecret)
		if err != nil {
			return spec, err
		}

		err = b.GiteaClient.DeleteDeployKey(owner, repoName, key.KeyID)

		if err != nil {
			if err.Error() != gitea.NotFoundError {
				return spec, errors.New("couldn't deprovision instance")
			}
		}
	}

	err = b.Client.Delete(ctx, bindingSecret)
	if err != nil {
		return spec, errors.New("couldn't unbind instance")
	}

	return spec, nil
}

// nolint: golint
func (b *GiteaServiceBroker) LastOperation(ctx context.Context, instanceID string, details brokerapi.PollDetails) (brokerapi.LastOperation, error) {
	return brokerapi.LastOperation{}, ErrNotImplemented
}

// nolint: golint
func (b *GiteaServiceBroker) Update(cxt context.Context, instanceID string, details brokerapi.UpdateDetails, asyncAllowed bool) (brokerapi.UpdateServiceSpec, error) {
	return brokerapi.UpdateServiceSpec{}, ErrNotImplemented
}

// nolint: golint
func (b *GiteaServiceBroker) LastBindingOperation(ctx context.Context, instanceID, bindingID string, details brokerapi.PollDetails) (brokerapi.LastOperation, error) {
	return brokerapi.LastOperation{}, ErrNotImplemented
}

func (b *GiteaServiceBroker) _getRepository(ctx context.Context, Secret *corev1.Secret) (*giteasdk.Repository, error) {
	user, name, err := getRepositoryIdentity(Secret)
	if err != nil {
		return nil, err
	}

	return b.GiteaClient.GetRepo(user, name)
}

func (b *GiteaServiceBroker) validateBindingInstanceRelationship(instanceSecret, bindingSecret *corev1.Secret) error {
	if getInstanceKeyName(string(bindingSecret.Data["instance_id"])) != instanceSecret.GetName() {
		return brokerapi.NewFailureResponse(
			errors.New("binding doesn't correspond to given instance"), http.StatusBadRequest, "bad-request",
		)
	}

	return nil
}

func (b *GiteaServiceBroker) _getDeployKey(ctx context.Context, instanceSecret, bindingSecret *corev1.Secret) (*giteasdk.DeployKey, error) {
	user, repo, fingerprint, title, err := getDeployKeyIdentity(instanceSecret, bindingSecret)
	if err != nil {
		return nil, errors.New("unknown deploy key details")
	}

	deployKeys, err := b.GiteaClient.ListDeployKeys(user, repo)
	if err != nil {
		if err.Error() == gitea.NotFoundError {
			return nil, ErrInstanceNotFound
		}

		log.V(2).Info("couldn't list repo deploy keys", "response", err.Error(), "user", user, "repo", repo)
		return nil, err
	}

	for _, key := range deployKeys {
		if key.Fingerprint == fingerprint {
			if key.Title != title {
				return nil, brokerapi.ErrBindingAlreadyExists
			}
			return key, nil
		}
	}
	return nil, brokerapi.ErrBindingNotFound
}

func (b *GiteaServiceBroker) getInstance(ctx context.Context, instanceID string) (*giteasdk.Repository, error) {
	secret := &corev1.Secret{}
	key := b.getInstanceKey(instanceID)

	err := b.Client.Get(ctx, key, secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("secret not found", "instance_id", instanceID, "secret", key)
			return nil, ErrInstanceNotFound
		}
		log.Error(err, "couldn't get secret", "instance_id", instanceID, "secret", key)
		return nil, errors.New("couldn't get instance")
	}

	repo, err := b._getRepository(ctx, secret)

	if err == nil {
		return repo, nil
	}

	_, name, idErr := getRepositoryIdentity(secret)
	if idErr != nil {
		return nil, ErrInstanceNotFound
	}

	if err.Error() == gitea.NotFoundError {
		log.V(1).Info("repository not found", "instance_id", instanceID, "repository_name", name)
		return nil, ErrInstanceNotFound
	}
	log.Error(err, "couldn't get repository", "instance_id", instanceID, "repository_name", name)
	return nil, errors.New("couldn't get instance")
}

func (b *GiteaServiceBroker) getOrCreateBinding(ctx context.Context, instanceID, bindingID string,
	instanceSecret *corev1.Secret, params BindingParameters) (*giteasdk.DeployKey, error) {
	user, name, err := getRepositoryIdentity(instanceSecret)
	if err != nil {
		return nil, err
	}

	fingerprint, err := getPublicKeyFingerprint(params.PublicKey)
	if err != nil {
		return nil, err
	}
	fingerprint = fmt.Sprintf("SHA256:%s", fingerprint)

	data := map[string][]byte{
		"instance_id": []byte(instanceID),
		"title":       []byte(params.Title),
		"public_key":  []byte(params.PublicKey),
		"fingerprint": []byte(fingerprint),
	}
	bindingSecret := &corev1.Secret{Data: data}
	bindingSecretCreated, err := b.getOrCreateBindingSecret(ctx, bindingID, bindingSecret)
	if err != nil {
		return nil, errors.New("couldn't create binding")
	}

	// the binding already existed
	if !bindingSecretCreated {
		// compare given parameters to existing binding parameters
		for key, param := range data {
			if !bytes.Equal(bindingSecret.Data[key], param) {
				return nil, brokerapi.ErrBindingAlreadyExists
			}
		}

		//
		key, err := b._getDeployKey(ctx, instanceSecret, bindingSecret)
		if err == nil {
			return key, nil
		} else if err == ErrInstanceNotFound ||
			err == brokerapi.ErrBindingNotFound ||
			err == brokerapi.ErrBindingAlreadyExists {
			return nil, err
		}
		return nil, errors.New("couldn't get existing binding")
	}

	// create the deploy key
	key, err := b.GiteaClient.CreateDeployKey(user, name, giteasdk.CreateKeyOption{
		Title: params.Title,
		Key:   params.PublicKey,
	})
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (b *GiteaServiceBroker) provisionInstance(ctx context.Context, instanceID string, params ProvisionParameters) (*giteasdk.Repository, error) {
	data := map[string][]byte{
		"repository_owner": []byte(params.RepositoryOwner),
		"repository_name":  []byte(params.RepositoryName),
		"migrate_url":      []byte(params.MigrateURL),
	}

	Secret := &corev1.Secret{Data: data}

	SecretCreated, err := b.getOrCreateInstanceSecret(ctx, instanceID, Secret)
	if err != nil {
		return nil, errors.New("couldn't provision instance")
	}

	// the Secret existed already, so let's try and retrieve the repository
	if !SecretCreated {
		SecretKey, err := client.ObjectKeyFromObject(Secret)
		if err != nil {
			return nil, errors.New("couldn't get repository identity")
		}

		log.Info("instance Secret already existed", "instance_id", instanceID, "Secret", SecretKey)

		user, name, err := getRepositoryIdentity(Secret)
		if err != nil {
			return nil, errors.New("couldn't get repository identity")
		}

		// compare given parameters to existing instance parameters
		for key, param := range data {
			if !bytes.Equal(Secret.Data[key], param) {
				log.Info("received parameters were different from existing instance parameters")
				return nil, brokerapi.ErrInstanceAlreadyExists
			}
		}

		repo, err := b.GiteaClient.GetRepo(user, name)
		if err == nil {
			return repo, nil
		} else if err.Error() != gitea.NotFoundError {
			log.Error(err, "error while retrieving repository info", "instance_id", instanceID, "repository_name", name)

			return nil, errors.New("couldn't get existing instance")
		} else {
			log.Error(err, "found provisioned Secret, but no repository",
				"instance_id", instanceID, "secret", SecretKey, "repository_name", Secret.Data["repository_name"])
			// provisioning is done below
		}
	}

	// the repository needs to be created
	return b.createInstance(ctx, instanceID, params)
}

func (b *GiteaServiceBroker) createInstance(ctx context.Context, instanceID string, params ProvisionParameters) (repository *giteasdk.Repository, err error) {
	if params.MigrateURL != "" {
		return b.migrateRepo(ctx, instanceID, params)
	} else {
		log.Info("creating repository", "repository_name", params.RepositoryName, "repository_owner", params.RepositoryOwner)
		repository, err = b.GiteaClient.AdminCreateRepo(params.RepositoryOwner, giteasdk.CreateRepoOption{
			Name:    params.RepositoryName,
			Private: true,
		})
		if err != nil {
			log.Error(err, "couldn't provision repository", "instance_id", instanceID)
			return nil, errors.New("couldn't provision repository")
		}
	}
	return repository, nil
}

func (b *GiteaServiceBroker) migrateRepo(ctx context.Context, instanceID string, params ProvisionParameters) (*giteasdk.Repository, error) {
	// Get repo owner / organization ID
	giteaOrg, err := b.GiteaClient.GetOrg(params.RepositoryOwner)
	if err != nil {
		return nil, errors.New("could not retrieve the given repository_organization details")
	}
	uid := int(giteaOrg.ID)

	log.Info("creating repository", "migrate_url", params.MigrateURL, "repository_name", params.RepositoryName, "UID", uid)
	repository, err := b.GiteaClient.MigrateRepo(giteasdk.MigrateRepoOption{
		CloneAddr: params.MigrateURL,
		RepoName:  params.RepositoryName,
		UID:       uid,
	})
	if err != nil {
		return nil, errors.New("couldn't migrate given repository")
	}
	return repository, nil
}

// getPublicKeyFingerprint parses an OpenSSH public key and returns it's fingerprint
func getPublicKeyFingerprint(pubAuthKey string) (string, error) {
	out, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubAuthKey))
	if err != nil {
		return "", errors.New("failed to parse Authorized encoded public key: " + err.Error())
	}
	return fingerprintSHA256(out), nil
}

// fingerprintSHA256 returns base64 sha256 hash with the trailing equal sign removed
func fingerprintSHA256(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	b64hash := base64.StdEncoding.EncodeToString(hash[:])
	return strings.TrimRight(b64hash, "=")
}

func AddToManager(mgr manager.Manager) error { // nolint: golint
	giteaClient := giteasdk.NewClient(options.GiteaURL, options.GiteaAdminAccessToken)
	srv := NewBrokerServer(":8080", giteaClient, mgr)
	return mgr.Add(srv)
}
