package broker

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strconv"
	"time"

	"code.gitea.io/sdk/gitea"
	"github.com/google/uuid"
	"github.com/pivotal-cf/brokerapi"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

// nolint: golint
var (
	ProvisioningStatus   = "provisioning"
	ProvisionedStatus    = "provisioned"
	DeprovisioningStatus = "deprovisioning"
	BindingStatus        = "binding"
	BoundStatus          = "bound"
	UnbindingStatus      = "unbinding"
)

type Binding struct {
	HostURL   string
	CloneURL  string
	PublicKey string
}

type ProvisionParameters struct {
	RepositoryName         string `json:"repository_name"`
	RepositoryOrganization string `json:"repository_organization"`
	RepositoryOwner        string `json:"repository_owner"`
	MigrateURL             string `json:"migrate_url"`
}

type BindingParameters struct {
	Title     string `json:"title"`
	PublicKey string `json:"public_key"`
}

type GiteaServiceBroker struct {
	client.Client
	GiteaClient
}

var notImplementedError = brokerapi.NewFailureResponse(errors.New("not implemented"), http.StatusNotImplemented, "not-implemented")

func (b *GiteaServiceBroker) Provision(ctx context.Context, instanceID string, provisionDetails brokerapi.ProvisionDetails, asyncAllowed bool) (spec brokerapi.ProvisionedServiceSpec, err error) {
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

	if parameters.RepositoryOwner != "" && parameters.RepositoryOrganization != "" {
		errorList = append(errorList, errors.New("can not specify both `repository_owner` and `repository_organization`"))
	}

	if parameters.RepositoryOwner == "" && parameters.RepositoryOrganization == "" {
		errorList = append(errorList, errors.New("you must specify a `repository_owner` or a `repository_organization`"))
	}

	err = utilerrors.Flatten(utilerrors.NewAggregate(errorList))
	if err != nil {
		return spec, brokerapi.NewFailureResponse(err, http.StatusBadRequest, "bad-request")
	}

	// Create the repository
	repository, err := b.createInstance(ctx, instanceID, parameters)
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
	spec.PlanID = ""
	spec.ServiceID = ""

	return spec, nil
}

func (b *GiteaServiceBroker) Deprovision(ctx context.Context, instanceID string, details brokerapi.DeprovisionDetails, asyncAllowed bool) (brokerapi.DeprovisionServiceSpec, error) {
	spec := brokerapi.DeprovisionServiceSpec{}

	configMap, err := b.getInstanceConfigMap(ctx, instanceID)
	if err != nil {
		return spec, err
	}

	owner, err := getRepositoryOwner(configMap)
	if err != nil {
		return spec, errors.New("couldn't deprovision instance")
	}

	err = b.GiteaClient.DeleteRepo(owner, configMap.Data["name"])
	if err != nil {
		// TODO when gitea fixes this and returns success for attempting a delete on
		// unexisting repository remove _getRepository below

		// if the repo is not already deleted, return error
		_, err := b._getRepository(ctx, configMap)
		if err == nil || err.Error() != GiteaNotFoundError {
			return spec, errors.New("couldn't deprovision instance")
		}
	}

	spec.IsAsync = false

	err = b.Client.Delete(ctx, configMap)
	if err != nil {
		return spec, errors.New("couldn't deprovision instance")
	}

	return spec, nil
}

func (b *GiteaServiceBroker) Bind(ctx context.Context, instanceID, bindingID string, details brokerapi.BindDetails, asyncAllowed bool) (brokerapi.Binding, error) {
	binding := brokerapi.Binding{}

	// get and validate the binding parameters
	parameters := BindingParameters{}
	err := json.Unmarshal(details.GetRawParameters(), &parameters)
	if err != nil {
		return binding, err
	}

	if parameters.Title == "" {
		parameters.Title, err = uuid.NewRandom()
		if err != nil {
			log.Error(err, "couldn't generate a deploy key title")
			return binding, errors.New("couldn't generate a title")
		}
	}
	var publicKey, privateKey string
	if parameters.PublicKey == "" {
		publicKey, privateKey, err = generatePEMKeyPair()
		if err != nil {
			return binding, err
		}
	}

	_, err = b.createBinding(ctx, instanceID, bindingID, parameters)
	if err != nil {
		return binding, err
	}

	binding.Credentials = map[string]string{
		"private_key": privateKey,
		"public_key":  publicKey,
	}
	return binding, nil
}

func (b *GiteaServiceBroker) createBinding(ctx context.Context, instanceID, bindingID string, params BindingParameters) (*gitea.DeployKey, error) {
	instanceConfigMap, err := b.getInstanceConfigMap(ctx, instanceID)
	if err != nil {
		return nil, err
	}

	data := map[string]string{
		"status":      BindingStatus,
		"instance_id": instanceID,
	}
	bindingConfigMap := &corev1.ConfigMap{Data: data}
	bindingConfigMapCreated, err := b.getOrCreateBindingMap(ctx, bindingID, bindingConfigMap)
	if err != nil {
		return nil, errors.New("couldn't create binding")
	}

	repoName := instanceConfigMap.Data["name"]
	user, err := getRepositoryOwner(instanceConfigMap)
	if err != nil {
		return nil, brokerapi.ErrInstanceDoesNotExist
	}

	// check if the binding already existed
	if !bindingConfigMapCreated {
		// check the binding is reprovisioned for same instance
		if bindingConfigMap.Data["instance_id"] != instanceID {
			return nil, brokerapi.ErrBindingAlreadyExists
		}

		// compare given parameters to existing binding parameters
		for _, param := range []string{params.Title} {
			if bindingConfigMap.Data[param] != data[param] {
				return nil, brokerapi.ErrBindingAlreadyExists
			}
		}

		return b._getBinding(ctx, instanceConfigMap, bindingConfigMap)
	}

	// create the deploy key
	key, err := b.GiteaClient.CreateDeployKey(user, repoName, gitea.CreateKeyOption{
		Title: params.Title,
		Key:   params.PublicKey,
	})
	if err != nil {
		return nil, err
	}

	// update the bindingConfigMap
	bindingConfigMap.Data["status"] = BoundStatus
	bindingConfigMap.Data["id"] = strconv.Itoa(int(key.KeyID))
	b.Client.Update(ctx, bindingConfigMap)

	return key, nil
}

func (b *GiteaServiceBroker) _getBinding(ctx context.Context, instanceConfigMap, bindingConfigMap *corev1.ConfigMap) (*gitea.DeployKey, error) {
	// the binding is still on-going
	if bindingConfigMap.Data["status"] == BindingStatus {
		return nil, brokerapi.ErrBindingNotFound
	} else if bindingConfigMap.Data["status"] == BoundStatus {
		key, err := b._getDeployKey(ctx, instanceConfigMap, bindingConfigMap)
		if err == nil {
			return key, nil
		} else if err.Error() != GiteaNotFoundError {
			return nil, brokerapi.ErrBindingNotFound
		} else {
			return nil, errors.New("couldn't get existing binding")
		}
	} else if bindingConfigMap.Data["status"] == UnbindingStatus {
		// the key is currently being removed, the reasonable
		// response here is that it already exists
		return nil, brokerapi.ErrBindingAlreadyExists
	}
	// TODO log unexpected status
	return nil, brokerapi.ErrBindingAlreadyExists
}

// GetBinding returns a Gitea DeployKey info
func (b *GiteaServiceBroker) GetBinding(ctx context.Context, instanceID, bindingID string) (brokerapi.GetBindingSpec, error) {
	spec := brokerapi.GetBindingSpec{}

	instanceConfigMap, err := b.getInstanceConfigMap(ctx, instanceID)
	if err != nil {
		return spec, err
	}

	bindingConfigMap, err := b.getBindingConfigMap(ctx, bindingID)
	if err != nil {
		return spec, err
	}

	if err = b.validateBindingInstanceRelationship(instanceConfigMap, bindingConfigMap); err != nil {
		return spec, err
	}

	key, err := b._getBinding(ctx, instanceConfigMap, bindingConfigMap)
	if err != nil {
		return spec, err
	}

	params := BindingParameters{
		Title:     key.Title,
		PublicKey: key.Key,
	}
	spec.Parameters, err = json.Marshal(params)

	if err != nil {
		return spec, errors.New("couldn't fetch binding")
	}

	return spec, nil
}

// Unbind deletes a Gitea DeployKey
func (b *GiteaServiceBroker) Unbind(ctx context.Context, instanceID, bindingID string, details brokerapi.UnbindDetails, asyncAllowed bool) (brokerapi.UnbindSpec, error) {
	spec := brokerapi.UnbindSpec{}

	instanceConfigMap, err := b.getInstanceConfigMap(ctx, instanceID)
	if err != nil {
		return spec, err
	}

	bindingConfigMap, err := b.getBindingConfigMap(ctx, bindingID)
	if err != nil {
		return spec, err
	}

	if err = b.validateBindingInstanceRelationship(instanceConfigMap, bindingConfigMap); err != nil {
		return spec, err
	}

	owner, repoName, keyID, err := b._getDeployKeyIdentity(instanceConfigMap, bindingConfigMap)
	if err != nil {
		return spec, nil
	}

	err = b.GiteaClient.DeleteDeployKey(owner, repoName, keyID)
	if err != nil {
		// TODO when gitea fixes this and returns success for attempting a delete on
		// unexisting repository remove _getRepository below

		// if the repo is not already deleted, return error
		_, err := b._getDeployKey(ctx, instanceConfigMap, bindingConfigMap)
		if err == nil || err.Error() != GiteaNotFoundError {
			return spec, errors.New("couldn't deprovision instance")
		}
	}

	return spec, nil
}

// nolint: golint
func (b *GiteaServiceBroker) LastOperation(ctx context.Context, instanceID string, details brokerapi.PollDetails) (brokerapi.LastOperation, error) {
	return brokerapi.LastOperation{}, notImplementedError
}

// nolint: golint
func (b *GiteaServiceBroker) Update(cxt context.Context, instanceID string, details brokerapi.UpdateDetails, asyncAllowed bool) (brokerapi.UpdateServiceSpec, error) {
	return brokerapi.UpdateServiceSpec{}, notImplementedError
}

// nolint: golint
func (b *GiteaServiceBroker) LastBindingOperation(ctx context.Context, instanceID, bindingID string, details brokerapi.PollDetails) (brokerapi.LastOperation, error) {
	return brokerapi.LastOperation{}, notImplementedError
}

func (b *GiteaServiceBroker) _getRepository(ctx context.Context, configMap *corev1.ConfigMap) (*gitea.Repository, error) {
	user, err := getRepositoryOwner(configMap)
	if err != nil {
		return nil, errors.New("unknown repository owner")
	}

	return b.GiteaClient.GetRepo(user, configMap.Data["name"])
}

func (b *GiteaServiceBroker) validateBindingInstanceRelationship(instanceConfigMap, bindingConfigMap *corev1.ConfigMap) error {
	if bindingConfigMap.Data["instance_id"] != instanceConfigMap.GetName() {
		return errors.New("binding doesn't correspond to given instance")
	}

	return nil
}

func (b *GiteaServiceBroker) _getDeployKey(ctx context.Context, instanceConfigMap, bindingConfigMap *corev1.ConfigMap) (*gitea.DeployKey, error) {
	user, repo, keyID, err := b._getDeployKeyIdentity(instanceConfigMap, bindingConfigMap)
	if err != nil {
		return nil, errors.New("unknown deploy key details")
	}

	return b.GiteaClient.GetDeployKey(user, repo, keyID)
}

func (b *GiteaServiceBroker) _getDeployKeyIdentity(instanceConfigMap, bindingConfigMap *corev1.ConfigMap) (user, repo string, id int64, err error) {
	repo = instanceConfigMap.Data["name"]
	if user, err = getRepositoryOwner(instanceConfigMap); err != nil {
		err = brokerapi.ErrInstanceDoesNotExist
		return
	}

	if id, err = strconv.ParseInt(bindingConfigMap.Data["id"], 10, 64); err != nil {
		err = brokerapi.ErrBindingNotFound
	}
	return
}

func (b *GiteaServiceBroker) getInstance(ctx context.Context, instanceID string) (*gitea.Repository, error) {
	configMap := &corev1.ConfigMap{}
	key := b.getInstanceKey(instanceID)

	err := b.Client.Get(ctx, key, configMap)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("config map not found", "instance_id", instanceID, "config_map", key)
			return nil, brokerapi.ErrInstanceDoesNotExist
		}
		log.Error(err, "couldn't get config map", "instance_id", instanceID, "config_map", key)
		return nil, errors.New("couldn't get instance")
	}

	repo, err := b._getRepository(ctx, configMap)

	if err == nil {
		return repo, nil
	} else if err.Error() != GiteaNotFoundError {
		log.V(1).Info("repository not found", "instance_id", instanceID, "repository_name", configMap.Data["name"])
		return nil, brokerapi.ErrInstanceDoesNotExist
	} else {
		log.Error(err, "couldn't get repository", "instance_id", instanceID, "repository_name", configMap.Data["name"])
		return nil, errors.New("couldn't get instance")
	}
}

func generatePEMKeyPair() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", err
	}
	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyDer,
	}
	privateKeyPEM := string(pem.EncodeToMemory(&privateKeyBlock))

	publicKey := privateKey.PublicKey
	publicKeyDer, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return "", "", err
	}

	publicKeyBlock := pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyDer,
	}
	publicKeyPEM := string(pem.EncodeToMemory(&publicKeyBlock))

	return publicKeyPEM, privateKeyPEM, nil
}

func (b *GiteaServiceBroker) createInstance(ctx context.Context, instanceID string, params ProvisionParameters) (*gitea.Repository, error) {
	data := map[string]string{
		"status":                   ProvisioningStatus,
		"org":                      params.RepositoryOrganization,
		"owner":                    params.RepositoryOwner,
		"name":                     params.RepositoryName,
		"migrate_url":              params.MigrateURL,
		"last_operation_timestamp": time.Now().Format(time.RFC3339),
	}

	configMap := &corev1.ConfigMap{Data: data}

	configMapCreated, err := b.getOrCreateServiceMap(ctx, instanceID, configMap)
	if err != nil {
		return nil, errors.New("couldn't provision instance")
	}

	// the configmap existed already, so let's try and retrieve the repository
	if !configMapCreated {
		configMapKey, err := client.ObjectKeyFromObject(configMap)
		if err != nil {
			return nil, brokerapi.ErrInstanceDoesNotExist
		}

		log.V(0).Info("instance configmap already existed", "instance_id", instanceID, "configMap", configMapKey)

		user, err := getRepositoryOwner(configMap)
		if err != nil {
			return nil, brokerapi.ErrInstanceDoesNotExist
		}

		// compare given parameters to existing instance parameters
		for _, param := range []string{"repository_name", "repository_organization", "repository_owner", "migrate_url"} {
			if configMap.Data[param] != data[param] {
				log.V(0).Info("received parameters were different to existing instance parameters")
				return nil, brokerapi.ErrInstanceAlreadyExists
			}
		}

		// the instance is currently provisioning
		if configMap.Data["status"] == ProvisioningStatus {
			// check if the repo has been initialized
			repo, err := b.GiteaClient.GetRepo(user, configMap.Data["name"])
			if err != nil {
				if err.Error() != GiteaNotFoundError {
					log.V(1).Info("found provisioning configmap, but no repository", "instance_id", instanceID, "config_map", configMapKey, "repository_name", configMap.Data["name"])
				} else {
					log.Error(err, "error while retrieving repository info", "instance_id", instanceID, "repository_name", configMap.Data["name"])
				}
				return nil, brokerapi.ErrInstanceDoesNotExist
			}

			configMap.Data["status"] = ProvisionedStatus
			b.Client.Update(ctx, configMap)

			return repo, nil
		} else if configMap.Data["status"] == ProvisionedStatus {
			repo, err := b.GiteaClient.GetRepo(user, configMap.Data["name"])
			if err == nil {
				// TODO check if the instance still has the same name and owner
				return repo, nil
			} else if err.Error() != GiteaNotFoundError {
				log.Error(err, "found provisioned configmap, but no repository", "instance_id", instanceID, "config_map", configMapKey, "repository_name", configMap.Data["name"])
				return nil, brokerapi.ErrInstanceDoesNotExist
			} else {
				log.Error(err, "error while retrieving repository info", "instance_id", instanceID, "repository_name", configMap.Data["name"])
				return nil, errors.New("couldn't get existing instance")
			}
		} else if configMap.Data["status"] == DeprovisioningStatus {
			// the instance is currently being deprovisioned, the reasonable
			// response here is that it already exists
			log.V(1).Info("tried to provision an instance that is currently deprovisioning", "instance_id", instanceID)
			return nil, brokerapi.ErrInstanceAlreadyExists
		}

		// TODO log unexpected status
		return nil, brokerapi.ErrInstanceAlreadyExists
	}

	// the instance needs to be provisioned

	var repository *gitea.Repository

	if params.MigrateURL != "" {
		// Get repo owner / organization ID
		uid := -1
		if params.RepositoryOrganization != "" {
			giteaOrg, err := b.GiteaClient.GetOrg(params.RepositoryOrganization)
			if err != nil {
				return nil, errors.New("could not retrieve the given repository_organization details")
			}
			uid = int(giteaOrg.ID)
		} else if params.RepositoryOwner != "" {
			giteaUser, err := b.GiteaClient.GetUserInfo(params.RepositoryOwner)
			if err != nil {
				return nil, errors.New("could not retrieve the given repository_owner details")
			}
			uid = int(giteaUser.ID)
		} else {
			// this case is currently handled by previous validation, so this should be unreachable
			return nil, errors.New("default organization not implemented")
		}

		log.V(0).Info("creating repository", "migrate_url", params.MigrateURL, "repository_name", params.RepositoryName, "UID", uid)
		repository, err = b.GiteaClient.MigrateRepo(gitea.MigrateRepoOption{
			CloneAddr: params.MigrateURL,
			RepoName:  params.RepositoryName,
			UID:       uid,
		})
		if err != nil {
			return nil, errors.New("couldn't migrate given repository")
		}
	} else {
		if params.RepositoryOwner != "" {
			log.V(0).Info("creating repository", "repository_name", params.RepositoryName, "repository_owner", params.RepositoryOwner)
			repository, err = b.GiteaClient.AdminCreateRepo(params.RepositoryOwner, gitea.CreateRepoOption{
				Name: params.RepositoryName,
			})
			if err != nil {
				log.Error(err, "couldn't provision repository", "instance_id", instanceID)
				return nil, errors.New("couldn't provision repository")
			}
		} else if params.RepositoryOrganization != "" {
			log.V(0).Info("creating repository", "repository_name", params.RepositoryName, "repository_organization", params.RepositoryOrganization)
			repository, err = b.GiteaClient.AdminCreateRepo(params.RepositoryOrganization, gitea.CreateRepoOption{
				Name: params.RepositoryName,
			})
			if err != nil {
				log.Error(err, "couldn't provision repository", "instance_id", instanceID)
				return nil, errors.New("couldn't provision repository")
			}
		} else {
			// this case is currently handled by previous validation, so this should be unreachable
			return nil, errors.New("default organization not implemented")
		}
	}

	configMap.Data["status"] = ProvisionedStatus
	err = b.Client.Update(ctx, configMap)
	if err != nil {
		log.Error(err, "couldn't update instance config map", "instance_id", instanceID, "config_map")
		return repository, err
	}
	return repository, nil
}

func AddToManager(mgr manager.Manager) error { // nolint: golint
	srv := NewBrokerServer(":8080", mgr)
	return mgr.Add(srv)
}
