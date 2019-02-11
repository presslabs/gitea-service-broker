package broker

import (
	"context"

	"github.com/pivotal-cf/brokerapi"

	"github.com/presslabs/gitea-service-broker/pkg/cmd/options"
)

var sharedPlan = brokerapi.ServicePlan{
	ID:          options.SharedPlanID,
	Name:        options.SharedPlanName,
	Description: "This plan provides a Gitea repository on a shared VM configured for data persistence.",
	Metadata: &brokerapi.ServicePlanMetadata{
		Bullets: []string{
			"Each instance shares the same VM",
			"Single dedicated Gitea process",
			"Suitable for development & testing workloads",
		},
		DisplayName: "Shared-VM",
	},
}

var planList = []brokerapi.ServicePlan{sharedPlan}

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
