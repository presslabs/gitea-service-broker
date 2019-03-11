package broker

import (
	"context"
	"errors"
	"fmt"
	"github.com/pivotal-cf/brokerapi"
	"github.com/presslabs/gitea-service-broker/pkg/cmd/options"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func getInstanceKeyName(instanceID string) string {
	return fmt.Sprintf("gsb-instance-%s", instanceID)
}

func getBindingKeyName(instanceID string) string {
	return fmt.Sprintf("gsb-binding-%s", instanceID)
}

func (giteaServiceBroker *GiteaServiceBroker) getBindingKey(bindingID string) client.ObjectKey {
	return client.ObjectKey{Name: getBindingKeyName(bindingID), Namespace: options.Namespace}
}

func (giteaServiceBroker *GiteaServiceBroker) getInstanceKey(instanceID string) client.ObjectKey {
	return client.ObjectKey{Name: getInstanceKeyName(instanceID), Namespace: options.Namespace}
}

func (giteaServiceBroker *GiteaServiceBroker) getInstanceSecret(ctx context.Context, instanceID string) (*corev1.Secret, error) {
	instanceSecret := &corev1.Secret{}
	key := giteaServiceBroker.getInstanceKey(instanceID)

	err := giteaServiceBroker.Client.Get(ctx, key, instanceSecret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, ErrInstanceNotFound
		}

		return nil, errors.New("couldn't fetch instance")
	}
	return instanceSecret, nil
}

func (giteaServiceBroker *GiteaServiceBroker) getBindingSecret(ctx context.Context, bindingID string) (*corev1.Secret, error) {
	bindingSecret := &corev1.Secret{}
	key := giteaServiceBroker.getBindingKey(bindingID)

	err := giteaServiceBroker.Client.Get(ctx, key, bindingSecret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, brokerapi.ErrBindingNotFound
		}

		return nil, errors.New("couldn't fetch binding")
	}
	return bindingSecret, nil
}

func (giteaServiceBroker *GiteaServiceBroker) getOrCreateInstanceSecret(ctx context.Context, instanceID string, secret *corev1.Secret) (bool, error) {
	secret.Labels = map[string]string{
		"app.kubernetes.io/component": "service-instance",
	}

	key := giteaServiceBroker.getInstanceKey(instanceID)

	created, err := getOrCreateSecret(ctx, giteaServiceBroker.Client, key, secret)
	if err != nil {
		log.Error(err, "unable to get or create instance secret")
	}
	return created, err
}

func (giteaServiceBroker *GiteaServiceBroker) getOrCreateBindingSecret(ctx context.Context, bindingID string, secret *corev1.Secret) (bool, error) {
	secret.Labels = map[string]string{
		"app.kubernetes.io/component": "service-binding",
	}

	key := giteaServiceBroker.getBindingKey(bindingID)

	created, err := getOrCreateSecret(
		ctx, giteaServiceBroker.Client, key, secret,
	)
	if err != nil {
		log.Error(err, "unable to get or create binding secret")
	}
	return created, err
}

func getRepositoryOwner(secret *corev1.Secret) (string, error) {
	if owner, ok := secret.Data["repository_owner"]; ok {
		return string(owner), nil
	} else if org, ok := secret.Data["repository_organization"]; ok {
		return string(org), nil
	}
	log.V(2).Info("repository owner not found", "secret", secret.Name)
	return "", errors.New("repository owner not found")
}

func getRepositoryIdentity(secret *corev1.Secret) (owner, name string, err error) {
	owner, err = getRepositoryOwner(secret)
	if err != nil {
		return
	}
	name = string(secret.Data["repository_name"])
	if name == "" {
		err = errors.New("repository name not found")
	}
	return
}

func getDeployKeyIdentity(instanceSecret, bindingSecret *corev1.Secret) (user, repo, fingerprint, title string,
	err error) {
	if user, repo, err = getRepositoryIdentity(instanceSecret); err != nil {
		err = ErrInstanceNotFound
		return
	}

	title = string(bindingSecret.Data["title"])

	fingerprint = string(bindingSecret.Data["fingerprint"])
	if fingerprint == "" {
		err = brokerapi.ErrBindingNotFound
	}
	return
}

func getOrCreateSecret(ctx context.Context, client client.Client, key client.ObjectKey, secret *corev1.Secret) (bool, error) {
	created := false
	err := client.Get(ctx, key, secret)

	if err != nil {
		if apierrors.IsNotFound(err) {
			secret.Labels["app.kubernetes.io/name"] = "gitea-service-broker"

			secret.SetNamespace(key.Namespace)
			secret.SetName(key.Name)
			err = client.Create(ctx, secret)
			created = true
		}
	}

	return created, err
}
