package broker

import (
	"context"

	"github.com/pivotal-cf/brokerapi"

	"github.com/presslabs/gitea-service-broker/pkg/cmd/options"
)

var defaultPlan = brokerapi.ServicePlan{
	ID:          options.DefaultPlanID,
	Name:        options.DefaultPlanName,
	Description: "This plan provides a Gitea repository",
	Metadata: &brokerapi.ServicePlanMetadata{
		Bullets:     []string{},
		DisplayName: "Repository",
	},
}

var planList = []brokerapi.ServicePlan{defaultPlan}

// Services returns a list of brokered services
func (giteaServiceBroker *GiteaServiceBroker) Services(ctx context.Context) ([]brokerapi.Service, error) {
	return []brokerapi.Service{
		{
			ID:          options.ServiceID,
			Name:        options.ServiceName,
			Description: "Gitea service broker for provisioning repositories",
			Bindable:    true,
			Plans:       planList,
			Metadata: &brokerapi.ServiceMetadata{
				DisplayName: "Gitea",
			},
			Tags: []string{
				"presslabs",
				"gitea",
				"git",
			},
		},
	}, nil
}
