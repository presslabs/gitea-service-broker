package broker

import (
	"context"
	"errors"
	"fmt"

	"github.com/pivotal-cf/brokerapi"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/presslabs/gitea-service-broker/pkg/cmd/options"
)

func getInstanceKeyName(instanceID string) string {
	return fmt.Sprintf("gsb-instance-%s", instanceID)
}

func getBindingKeyName(bindingID string) string {
	return fmt.Sprintf("gsb-binding-%s", bindingID)
}

func (giteaServiceBroker *giteaServiceBroker) getBindingKey(bindingID string) client.ObjectKey {
	return client.ObjectKey{Name: getBindingKeyName(bindingID), Namespace: options.Namespace}
}

func (giteaServiceBroker *giteaServiceBroker) getInstanceKey(instanceID string) client.ObjectKey {
	return client.ObjectKey{Name: getInstanceKeyName(instanceID), Namespace: options.Namespace}
}

func (giteaServiceBroker *giteaServiceBroker) getInstanceSecret(ctx context.Context, instanceID string) (*corev1.Secret, error) {
	instanceSecret := &corev1.Secret{}
	key := giteaServiceBroker.getInstanceKey(instanceID)

	err := giteaServiceBroker.Client.Get(ctx, key, instanceSecret)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, errInstanceNotFound
		}

		return nil, errors.New("couldn't fetch instance")
	}
	return instanceSecret, nil
}

func (giteaServiceBroker *giteaServiceBroker) getBindingSecret(ctx context.Context, bindingID string) (*corev1.Secret, error) {
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

func (giteaServiceBroker *giteaServiceBroker) getOrCreateInstanceSecret(ctx context.Context, instanceID string, secret *corev1.Secret) (bool, error) {
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

func (giteaServiceBroker *giteaServiceBroker) getOrCreateBindingSecret(ctx context.Context, bindingID string, secret *corev1.Secret) (bool, error) {
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

func getRepositoryIdentity(secret *corev1.Secret) (owner, name string, err error) {
	ownerBytes, ok := secret.Data["repository_owner"]
	if !ok {
		return "", "", errors.New("repository owner not found")
	}
	nameBytes, ok := secret.Data["repository_name"]
	if !ok {
		return "", "", errors.New("repository name not found")
	}
	return string(ownerBytes), string(nameBytes), nil
}

func getDeployKeyIdentity(instanceSecret, bindingSecret *corev1.Secret) (user, repo, fingerprint, title string,
	err error) {
	if user, repo, err = getRepositoryIdentity(instanceSecret); err != nil {
		err = errInstanceNotFound
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
	secret.Labels["app.kubernetes.io/name"] = "gitea-service-broker"
	secret.Namespace = key.Namespace
	secret.Name = key.Name
	err := client.Create(ctx, secret)

	if err != nil && !apierrors.IsAlreadyExists(err) {
		return false, err
	}

	if err == nil {
		return true, nil
	}

	return false, client.Get(ctx, key, secret)
}
