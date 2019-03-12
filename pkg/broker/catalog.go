package broker

import (
	"context"
	"fmt"

	"github.com/pivotal-cf/brokerapi"

	"github.com/presslabs/gitea-service-broker/pkg/cmd/options"
)

var boolTrue = true

var defaultPlan = brokerapi.ServicePlan{
	ID:          options.DefaultPlanID,
	Name:        options.DefaultPlanName,
	Description: "Creates a private repository for an organization",
	Free:        &boolTrue,
	Metadata: &brokerapi.ServicePlanMetadata{
		Bullets:     []string{},
		DisplayName: "Default",
	},
}

var planList = []brokerapi.ServicePlan{defaultPlan}

// Services returns a list of brokered services
func (giteaServiceBroker *GiteaServiceBroker) Services(ctx context.Context) ([]brokerapi.Service, error) {
	return []brokerapi.Service{
		{
			ID:          options.ServiceID,
			Name:        options.ServiceName,
			Description: fmt.Sprintf("Creates git repositories on Gitea at %s", options.GiteaURL),
			Bindable:    true,
			Plans:       planList,
			Metadata: &brokerapi.ServiceMetadata{
				DisplayName: "Git Repository",
			},
			Tags: []string{
				"presslabs",
				"gitea",
				"git",
			},
		},
	}, nil
}
