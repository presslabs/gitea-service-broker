package broker

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/alecthomas/jsonschema"
	"github.com/pivotal-cf/brokerapi"

	"github.com/presslabs/gitea-service-broker/pkg/cmd/options"
)

var boolTrue = true

var reflector = jsonschema.Reflector{
	ExpandedStruct: true,
}

var repoJSONSchemaBytes, _ = json.Marshal(reflector.Reflect(&ProvisionParameters{}))
var deployKeyJSONSchemaBytes, _ = json.Marshal(reflector.Reflect(&BindingParameters{}))

func (giteaServiceBroker *GiteaServiceBroker) repoPlans() []brokerapi.ServicePlan {
	plans := make([]brokerapi.ServicePlan, 1)

	repoSchema := brokerapi.Schema{}
	json.Unmarshal(repoJSONSchemaBytes, &repoSchema.Parameters)

	deployKeySchema := brokerapi.Schema{}
	json.Unmarshal(deployKeyJSONSchemaBytes, &deployKeySchema.Parameters)

	plans[0] = brokerapi.ServicePlan{
		ID:          options.DefaultPlanID,
		Name:        options.DefaultPlanName,
		Description: "Creates a private repository for an organization",
		Free:        &boolTrue,
		Metadata: &brokerapi.ServicePlanMetadata{
			Bullets:     []string{},
			DisplayName: "Default",
		},
		Schemas: &brokerapi.ServiceSchemas{
			Instance: brokerapi.ServiceInstanceSchema{
				Create: repoSchema,
			},
			Binding: brokerapi.ServiceBindingSchema{
				Create: deployKeySchema,
			},
		},
	}

	return plans
}

// Services returns a list of brokered services
func (giteaServiceBroker *GiteaServiceBroker) Services(ctx context.Context) ([]brokerapi.Service, error) {
	return []brokerapi.Service{
		{
			ID:          options.ServiceID,
			Name:        options.ServiceName,
			Description: fmt.Sprintf("Creates git repositories on Gitea at %s", options.GiteaURL),
			Bindable:    true,
			Plans:       giteaServiceBroker.repoPlans(),
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
