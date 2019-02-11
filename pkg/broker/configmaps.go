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

func (giteaServiceBroker *GiteaServiceBroker) getBindingKey(bindingID string) client.ObjectKey {
	return client.ObjectKey{Name: fmt.Sprintf("gsb-binding-%s", bindingID), Namespace: options.Namespace}
}

func (giteaServiceBroker *GiteaServiceBroker) getInstanceKey(instanceID string) client.ObjectKey {
	return client.ObjectKey{Name: fmt.Sprintf("gsb-instance-%s", instanceID), Namespace: options.Namespace}
}

func (giteaServiceBroker *GiteaServiceBroker) getInstanceConfigMap(ctx context.Context, instanceID string) (*corev1.ConfigMap, error) {
	instanceConfigMap := &corev1.ConfigMap{}
	key := giteaServiceBroker.getInstanceKey(instanceID)

	err := giteaServiceBroker.Client.Get(ctx, key, instanceConfigMap)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, brokerapi.ErrInstanceDoesNotExist
		}

		return nil, errors.New("")
	}
	return instanceConfigMap, nil
}

func (giteaServiceBroker *GiteaServiceBroker) getBindingConfigMap(ctx context.Context, bindingID string) (*corev1.ConfigMap, error) {
	bindingConfigMap := &corev1.ConfigMap{}
	key := giteaServiceBroker.getBindingKey(bindingID)

	err := giteaServiceBroker.Client.Get(ctx, key, bindingConfigMap)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, brokerapi.ErrBindingNotFound
		}

		return nil, errors.New("")
	}
	return bindingConfigMap, nil
}

func (giteaServiceBroker *GiteaServiceBroker) getOrCreateServiceMap(ctx context.Context, instanceID string, cm *corev1.ConfigMap) (bool, error) {
	key := giteaServiceBroker.getBindingKey(instanceID)

	created, err := getOrCreateConfigMap(ctx, giteaServiceBroker.Client, key, cm)
	if err != nil {
		log.Error(err, "unable to get or create service config map")
	}
	return created, err
}

func (giteaServiceBroker *GiteaServiceBroker) getOrCreateBindingMap(ctx context.Context, bindingID string, cm *corev1.ConfigMap) (bool, error) {
	key := giteaServiceBroker.getBindingKey(bindingID)

	created, err := getOrCreateConfigMap(
		ctx, giteaServiceBroker.Client, key, cm,
	)
	if err != nil {
		log.Error(err, "unable to get or create binding config map")
	}
	return created, err
}

func getRepositoryOwner(configMap *corev1.ConfigMap) (string, error) {
	if configMap.Data["owner"] != "" {
		return configMap.Data["owner"], nil
	} else if configMap.Data["org"] != "" {
		return configMap.Data["org"], nil
	}
	log.V(2).Info("repository owner not found", "config_map", configMap.Name)
	return "", errors.New("repository owner not found")
}

func getOrCreateConfigMap(ctx context.Context, client client.Client, key client.ObjectKey, cm *corev1.ConfigMap) (bool, error) {
	created := false
	err := client.Get(ctx, key, cm)

	if err != nil {
		if apierrors.IsNotFound(err) {
			cm.SetNamespace(key.Namespace)
			cm.SetName(key.Name)
			err = client.Create(ctx, cm)
			created = true
		}
	}

	return created, err
}
