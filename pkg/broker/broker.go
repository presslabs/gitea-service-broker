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
	"strconv"
	"strings"
	"time"

	giteasdk "code.gitea.io/sdk/gitea"
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

// ProvisionParameters contains the provision parameter fields
type ProvisionParameters struct {
	RepositoryName     string             `json:"repository_name"`
	RepositoryOwner    string             `json:"repository_owner"`
	MigrateURL         string             `json:"migrate_url,omitempty"`
	OrganizationPolicy organizationPolicy `json:"organization_policy,omitempty"`
}

type organizationPolicy string

const (
	organizationPolicyCreate      organizationPolicy = "create"
	organizationPolicyUseExisting organizationPolicy = "use-existing"
	defaultOrganizationPolicy                        = organizationPolicyCreate
)

// BindingParameters contains the binding parameter fields
type BindingParameters struct {
	ReadOnly bool `json:"read_only,omitempty"`
}

// BindingData contains the data required to create a binding
type BindingData struct {
	ReadOnly    bool   `json:"read_only"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
	InstanceID  string `json:"instance_id"`
	Title       string `json:"title"`
}

type giteaServiceBroker struct {
	client.Client
	GiteaClient gitea.Client
}

var (
	errNotImplemented = brokerapi.NewFailureResponse(errors.New("not implemented"), http.StatusNotImplemented,
		"not-implemented")
	errInstanceNotFound = brokerapi.NewFailureResponseBuilder(
		errors.New("instance cannot be fetched"), http.StatusNotFound, "instance-not-found",
	).Build()
)

// Provision implements Gitea service instance provisioning by creating a Repository
func (b *giteaServiceBroker) Provision(ctx context.Context, instanceID string, provisionDetails brokerapi.ProvisionDetails,
	asyncAllowed bool) (spec brokerapi.ProvisionedServiceSpec, err error) {
	log.Info("provisioning instance")

	// Get the provision parameters
	parameters := ProvisionParameters{OrganizationPolicy: defaultOrganizationPolicy}
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

// GetInstance implements Gitea service instance fetching by returning a Repository
func (b *giteaServiceBroker) GetInstance(ctx context.Context, instanceID string) (brokerapi.GetInstanceDetailsSpec, error) {
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

// Deprovision implements Gitea service instance deprovisioning by deleting a Repository
func (b *giteaServiceBroker) Deprovision(ctx context.Context, instanceID string, details brokerapi.DeprovisionDetails, asyncAllowed bool) (
	brokerapi.DeprovisionServiceSpec, error) {
	spec := brokerapi.DeprovisionServiceSpec{IsAsync: false}

	secret, err := b.getInstanceSecret(ctx, instanceID)
	if err != nil {
		if err == errInstanceNotFound {
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

// Bind implements Gitea service instance binding by creating a Deploy Key
func (b *giteaServiceBroker) Bind(ctx context.Context, instanceID, bindingID string, details brokerapi.BindDetails,
	asyncAllowed bool) (brokerapi.Binding, error) {
	binding := brokerapi.Binding{}

	repository, err := b.getInstance(ctx, instanceID)
	if err != nil {
		return binding, err
	}

	// get and validate the binding parameters
	parameters := BindingParameters{}

	if rawParameters := details.GetRawParameters(); len(rawParameters) > 0 {
		err = json.Unmarshal(rawParameters, &parameters)
		if err != nil {
			log.V(0).Info("couldn't unmarshal bind parameters",
				"raw_parameters", rawParameters, "msg", err.Error())

			return binding, err
		}
	}

	privateRSAKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return binding, err
	}
	privateRSAKeyDer := x509.MarshalPKCS1PrivateKey(privateRSAKey)
	privateRSAKeyBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateRSAKeyDer,
	}
	privateRSAKeyPEM := string(pem.EncodeToMemory(&privateRSAKeyBlock))

	publicRSAKey := privateRSAKey.PublicKey
	publicKey, err := ssh.NewPublicKey(&publicRSAKey)
	if err != nil {
		return binding, err
	}
	publicKeyOpenSSH := fmt.Sprintf("%s %s",
		publicKey.Type(),
		base64.StdEncoding.EncodeToString(publicKey.Marshal()),
	)

	if err != nil {
		return binding, err
	}

	_, err = b.getOrCreateBinding(ctx, instanceID, bindingID, publicKeyOpenSSH, parameters.ReadOnly)
	if err != nil {
		return binding, err
	}

	binding.Credentials = map[string]string{
		"id_rsa":         privateRSAKeyPEM,
		"id_rsa.pub":     publicKeyOpenSSH,
		"clone_http_url": repository.CloneURL,
		"clone_ssh_url":  repository.SSHURL,
	}

	return binding, nil
}

// Unbind implements Gitea service instance unbinding by deleting a Gitea DeployKey
func (b *giteaServiceBroker) Unbind(ctx context.Context, instanceID, bindingID string, details brokerapi.UnbindDetails, asyncAllowed bool) (brokerapi.UnbindSpec, error) {
	spec := brokerapi.UnbindSpec{}

	instanceSecret, err := b.getInstanceSecret(ctx, instanceID)
	if err != nil {
		if err == errInstanceNotFound {
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

	err = b.deleteDeployKey(ctx, instanceSecret, bindingSecret)
	return spec, err
}

// GetBinding cannot be implemented. Each call to bind creates a ssh key on the spot, without storing it
func (b *giteaServiceBroker) GetBinding(ctx context.Context, instanceID, bindingID string) (brokerapi.GetBindingSpec, error) {
	spec := brokerapi.GetBindingSpec{}
	return spec, errNotImplemented
}

// LastOperation cannot be implemented. Each operation is done synchronously and the result is not stored
func (b *giteaServiceBroker) LastOperation(ctx context.Context, instanceID string, details brokerapi.PollDetails) (brokerapi.LastOperation, error) {
	return brokerapi.LastOperation{}, errNotImplemented
}

// Update is not implemented as it is not in the scope of this project.
func (b *giteaServiceBroker) Update(cxt context.Context, instanceID string, details brokerapi.UpdateDetails, asyncAllowed bool) (brokerapi.UpdateServiceSpec, error) {
	return brokerapi.UpdateServiceSpec{}, errNotImplemented
}

// LastBindingOperation cannot be implemented. Each operation is done synchronously and the result is not stored
func (b *giteaServiceBroker) LastBindingOperation(ctx context.Context, instanceID, bindingID string, details brokerapi.PollDetails) (brokerapi.LastOperation, error) {
	return brokerapi.LastOperation{}, errNotImplemented
}

func (b *giteaServiceBroker) getDeployKeyAndShouldDelete(instanceSecret, bindingSecret *corev1.Secret) (*giteasdk.DeployKey, bool,
	error) {
	key, err := b._getDeployKey(instanceSecret, bindingSecret)
	// If the deploy key was found
	if err == nil {
		return key, true, nil
	}

	// If the deploy key was not found or was different from the expected one
	if err == errInstanceNotFound ||
		err == brokerapi.ErrBindingNotFound ||
		err == brokerapi.ErrBindingAlreadyExists {

		return key, false, nil
	}

	// If the operation timeout didn't pass yet, we consider the operation is still ongoing
	if time.Now().UTC().Sub(bindingSecret.GetCreationTimestamp().Time).Seconds() < options.OperationTimeout {
		return nil, false, brokerapi.ErrConcurrentInstanceAccess
	}

	// If we got an unexpected error
	return nil, false, err
}

func (b *giteaServiceBroker) deleteDeployKey(ctx context.Context, instanceSecret, bindingSecret *corev1.Secret) error {
	key, shouldDeleteKey, err := b.getDeployKeyAndShouldDelete(instanceSecret, bindingSecret)
	if err != nil {
		log.Error(err, "couldn't unbind instance")
		return errors.New("couldn't unbind instance")
	}

	if shouldDeleteKey {
		owner, repoName, _, _, idErr := getDeployKeyIdentity(instanceSecret, bindingSecret)
		if idErr != nil {
			return idErr
		}

		err = b.GiteaClient.DeleteDeployKey(owner, repoName, key.KeyID)

		if err != nil && err.Error() != gitea.NotFoundError {
			log.Error(err, "couldn't unbind instance")
			return errors.New("couldn't unbind instance")
		}
	}

	err = b.Client.Delete(ctx, bindingSecret)
	if err != nil {
		log.Error(err, "couldn't unbind instance")
		return errors.New("couldn't unbind instance")
	}

	return nil
}

func (b *giteaServiceBroker) validateBindingInstanceRelationship(instanceSecret, bindingSecret *corev1.Secret) error {
	if getInstanceKeyName(string(bindingSecret.Data["instance_id"])) != instanceSecret.GetName() {
		return brokerapi.NewFailureResponse(
			errors.New("binding doesn't correspond to given instance"), http.StatusBadRequest, "bad-request",
		)
	}

	return nil
}

func (b *giteaServiceBroker) _getDeployKey(instanceSecret, bindingSecret *corev1.Secret) (*giteasdk.DeployKey, error) {
	user, repo, fingerprint, title, err := getDeployKeyIdentity(instanceSecret, bindingSecret)
	if err != nil {
		return nil, errors.New("unknown deploy key details")
	}

	deployKeys, err := b.GiteaClient.ListDeployKeys(user, repo)
	if err != nil {
		if err.Error() == gitea.NotFoundError {
			return nil, errInstanceNotFound
		}

		log.V(1).Info("couldn't list repo deploy keys", "response", err.Error(), "user", user, "repo", repo)
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

func (b *giteaServiceBroker) getInstance(ctx context.Context, instanceID string) (*giteasdk.Repository, error) {
	secret := &corev1.Secret{}
	key := b.getInstanceKey(instanceID)

	err := b.Client.Get(ctx, key, secret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("secret not found", "instance_id", instanceID, "secret", key)
			return nil, errInstanceNotFound
		}
		log.Error(err, "couldn't get secret", "instance_id", instanceID, "secret", key)
		return nil, errors.New("couldn't get instance")
	}

	user, name, err := getRepositoryIdentity(secret)
	if err != nil {
		return nil, err
	}

	repo, err := b.GiteaClient.GetRepo(user, name)
	if err == nil {
		return repo, nil
	}

	if err.Error() == gitea.NotFoundError {
		log.V(1).Info("repository not found", "instance_id", instanceID, "repository_name", name)
		return nil, errInstanceNotFound
	}
	log.Error(err, "couldn't get repository", "instance_id", instanceID, "repository_name", name)
	return nil, errors.New("couldn't get instance")
}

func (b *giteaServiceBroker) getOrCreateBinding(ctx context.Context, instanceID, bindingID, publicKey string, readOnlyKey bool) (*giteasdk.DeployKey, error) {
	instanceSecret, err := b.getInstanceSecret(ctx, instanceID)
	if err != nil {
		return nil, err
	}

	// validate the instance identity secret before computing public key fingerprint
	_, _, err = getRepositoryIdentity(instanceSecret)
	if err != nil {
		return nil, err
	}

	fingerprint, err := getPublicKeyFingerprint(publicKey)
	if err != nil {
		return nil, err
	}
	fingerprint = fmt.Sprintf("SHA256:%s", fingerprint)
	data := BindingData{
		InstanceID:  instanceID,
		PublicKey:   publicKey,
		Fingerprint: fingerprint,
		ReadOnly:    readOnlyKey,
		Title:       bindingID,
	}

	return b.getOrCreateDeployKey(ctx, instanceSecret, bindingID, data)
}

func bindingDataToSecretData(data BindingData) map[string][]byte {
	secretData := map[string][]byte{
		"instance_id": []byte(data.InstanceID),
		"public_key":  []byte(data.PublicKey),
		"fingerprint": []byte(data.Fingerprint),
		"read_only":   []byte(strconv.FormatBool(data.ReadOnly)),
		"title":       []byte(data.Title),
	}

	return secretData
}

func (b *giteaServiceBroker) getOrCreateDeployKey(ctx context.Context, validInstanceSecret *corev1.Secret,
	bindingID string, data BindingData) (*giteasdk.DeployKey, error) {
	secretData := bindingDataToSecretData(data)
	bindingSecret := &corev1.Secret{Data: secretData}

	bindingSecretCreated, err := b.getOrCreateBindingSecret(ctx, bindingID, bindingSecret)
	if err != nil {
		return nil, errors.New("couldn't create binding")
	}

	// the binding already existed
	if !bindingSecretCreated {
		// compare expected parameters to existing binding parameters
		for param, expectedValue := range secretData {
			foundValue := bindingSecret.Data[param]
			if !bytes.Equal(expectedValue, foundValue) {
				log.V(0).Info("found unmatching binding secret param",
					"param", param, "expected_value", string(expectedValue), "found_value", string(foundValue))
				return nil, brokerapi.ErrBindingAlreadyExists
			}
		}

		// get existing deploy key
		key, keyErr := b._getDeployKey(validInstanceSecret, bindingSecret)
		if keyErr == nil {
			return key, nil
		} else if keyErr == errInstanceNotFound ||
			keyErr == brokerapi.ErrBindingNotFound ||
			keyErr == brokerapi.ErrBindingAlreadyExists {
			return nil, keyErr
		}
		return nil, errors.New("couldn't get existing binding")
	}

	owner, name, _ := getRepositoryIdentity(validInstanceSecret)

	// create the deploy key
	return b.GiteaClient.CreateDeployKey(owner, name, giteasdk.CreateKeyOption{
		Title:    data.Title,
		Key:      data.PublicKey,
		ReadOnly: data.ReadOnly,
	})
}

func (b *giteaServiceBroker) provisionInstance(ctx context.Context, instanceID string, params ProvisionParameters) (*giteasdk.Repository, error) {
	data := map[string][]byte{
		"repository_owner":    []byte(params.RepositoryOwner),
		"repository_name":     []byte(params.RepositoryName),
		"migrate_url":         []byte(params.MigrateURL),
		"organization_policy": []byte(params.OrganizationPolicy),
	}

	secret := &corev1.Secret{Data: data}

	secretCreated, err := b.getOrCreateInstanceSecret(ctx, instanceID, secret)
	if err != nil {
		return nil, errors.New("couldn't provision instance")
	}

	// the secret existed already, so let's try and retrieve the repository
	if !secretCreated {
		SecretKey, err := client.ObjectKeyFromObject(secret)
		if err != nil {
			return nil, errors.New("couldn't get repository identity")
		}

		log.Info("instance secret already existed", "instance_id", instanceID, "secret", SecretKey)

		user, name, err := getRepositoryIdentity(secret)
		if err != nil {
			return nil, errors.New("couldn't get repository identity")
		}

		// compare given parameters to existing instance parameters
		for param, expectedValue := range data {
			foundValue := secret.Data[param]
			if !bytes.Equal(secret.Data[param], expectedValue) {
				log.V(0).Info("found unmatching binding secret param",
					"param", param, "expected_value", string(expectedValue), "found_value", string(foundValue))
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
			log.Error(err, "found provisioned secret, but no repository",
				"instance_id", instanceID, "secret", SecretKey, "repository_name", secret.Data["repository_name"])
			// provisioning is done below
		}
	}

	// the repository needs to be created
	return b.createInstance(instanceID, params)
}

func (b *giteaServiceBroker) createInstance(instanceID string, params ProvisionParameters) (repository *giteasdk.Repository, err error) {
	if params.MigrateURL != "" {
		return b.migrateRepo(params)
	}
	if params.OrganizationPolicy == organizationPolicyCreate {
		_, err = b.GiteaClient.AdminCreateOrg(options.GiteaAdminUsername, giteasdk.CreateOrgOption{
			UserName: params.RepositoryOwner,
		})
		if err != nil && err.Error() != gitea.RepoAlreadyExistsError {
			log.Error(err, "couldn't create organization", "instance_id", instanceID, "organization_name", params.RepositoryOwner)

			return nil, errors.New("couldn't create organization")
		}
	}

	log.Info("creating repository", "repository_name", params.RepositoryName, "repository_owner", params.RepositoryOwner)
	repository, err = b.GiteaClient.AdminCreateRepo(params.RepositoryOwner, giteasdk.CreateRepoOption{
		Name:    params.RepositoryName,
		Private: true,
	})
	if err != nil {
		if err.Error() == gitea.NotFoundError {
			returnErr := errors.New("organization does not exist")

			if params.OrganizationPolicy != organizationPolicyUseExisting {
				log.Error(err, "couldn't provision repository", "instance_id", instanceID)
				returnErr = errors.New("couldn't provision repository")
			}

			return nil, brokerapi.NewFailureResponse(returnErr, http.StatusBadRequest,
				"bad-request")
		}
		log.Error(err, "couldn't provision repository", "instance_id", instanceID)

		return nil, errors.New("couldn't provision repository")
	}
	return repository, nil
}

func (b *giteaServiceBroker) migrateRepo(params ProvisionParameters) (*giteasdk.Repository, error) {
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
