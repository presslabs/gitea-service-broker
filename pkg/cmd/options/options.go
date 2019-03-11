package options

import (
	"errors"
	"net/url"
	"os"

	"github.com/spf13/pflag"
)

var (
	// ServiceID is the ID of the service
	ServiceID = "b431cc67-89fa-4f4a-8b1b-8f8a70c71b5e"
	// ServiceName is the name of the service
	ServiceName = "gitea"
	// SharedPlanID is the ID of the plan
	SharedPlanID = "3034df5d-c976-4265-87fd-7d3cfbe54a79"
	// SharedPlanName is the name of the shared plan
	SharedPlanName = "shared"
	// Username is used to connect to the broker API
	Username = ""
	// Password is used to connect to the broker API
	Password = ""
	// GiteaURL is the URL of the Gitea instance
	GiteaURL = ""
	// GiteaAdminAccessToken is the access token used to access the API
	GiteaAdminAccessToken = ""
	// GiteaAdminUsername is the username of the account that will own the resources
	GiteaAdminUsername = ""
	// Namespace where objects such as Secrets will be created
	Namespace = "default"
	// OperationTimeout is the number of seconds after which an operation that has not
	// finished is considered failed
	OperationTimeout = float64(61)
)

// AddToFlagSet add options to a FlagSet
func AddToFlagSet(flag *pflag.FlagSet) {
	flag.StringVar(&ServiceID, "service-id", ServiceID, "Service ID")
	flag.StringVar(&ServiceName, "service-name", ServiceName, "Service Name")
	flag.StringVar(&SharedPlanID, "shared-plan-id", SharedPlanID, "Shared Plan ID")
	flag.StringVar(&SharedPlanName, "shared-plan-name", SharedPlanName, "Shared Plan Name")
	flag.StringVar(&GiteaURL, "gitea-url", GiteaURL, "Gitea URL")
	flag.StringVar(&GiteaAdminAccessToken, "gitea-access-token", GiteaAdminAccessToken, "Token for accessing Gitea")
	flag.StringVar(&GiteaAdminUsername, "gitea-admin-username", GiteaAdminUsername, "User to be used for Gitea admin operations")
	flag.StringVar(&Namespace, "namespace", Namespace, "Namespace where objects such as secrets will be created")
	flag.Float64Var(&OperationTimeout, "operation-timeout", OperationTimeout, "Number of seconds after which an unfinished operation is failed")

}

// Validate validates the arguments
func Validate() error {
	_, err := url.Parse(GiteaURL)
	if err != nil {
		return err
	}

	if Username == "" {
		return errors.New("You must specify username")
	}

	if Password == "" {
		return errors.New("You must specify password")
	}

	if GiteaURL == "" {
		return errors.New("You must specify gitea-url")
	}

	if GiteaAdminAccessToken == "" {
		return errors.New("You must specify gitea-access-token")
	}

	if GiteaAdminUsername == "" {
		return errors.New("You must specify gitea-admin-username")
	}
	return nil
}

// LoadFromEnv fills in configs from environment variables
func LoadFromEnv() {
	prefix := "GSB_"

	envUsername := os.Getenv(prefix + "USERNAME")
	if len(envUsername) != 0 {
		Username = envUsername
	}

	envPassword := os.Getenv(prefix + "PASSWORD")
	if len(envPassword) != 0 {
		Password = envPassword
	}

	envGiteaURL := os.Getenv(prefix + "GITEA_URL")
	if len(envGiteaURL) != 0 {
		GiteaURL = envGiteaURL
	}

	envGiteaAdminAccessToken := os.Getenv(prefix + "GITEA_ADMIN_ACCESS_TOKEN")
	if len(envGiteaAdminAccessToken) != 0 {
		GiteaAdminAccessToken = envGiteaAdminAccessToken
	}

	envGiteaAdminUsername := os.Getenv(prefix + "GITEA_ADMIN_USERNAME")
	if len(envGiteaAdminUsername) != 0 {
		GiteaAdminUsername = envGiteaAdminUsername
	}
}
