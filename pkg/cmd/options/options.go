package options

import (
	"errors"
	"net/url"
	"os"

	"github.com/spf13/pflag"
)

var (
	ServiceID      = "b431cc67-89fa-4f4a-8b1b-8f8a70c71b5e"
	ServiceName    = "gitea"
	SharedPlanID   = "3034df5d-c976-4265-87fd-7d3cfbe54a79"
	SharedPlanName = "shared"
	// GiteaURL is the URL of the Gitea instance
	GiteaURL = ""
	// GiteaAdminAccessToken is the access token used to access the API
	GiteaAdminAccessToken = ""
	// GiteaAdminUsername is the username of the account that will own the resources
	GiteaAdminUsername = ""
	Namespace          = "default"
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
	flag.StringVar(&Namespace, "namespace", Namespace, "Namespace to be used for ConfigMaps")
}

// Validate validates the arguments
func Validate() error {
	_, err := url.Parse(GiteaURL)
	if err != nil {
		return err
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
	envGiteaURL := os.Getenv("GITEA_URL")
	if len(envGiteaURL) != 0 {
		GiteaURL = envGiteaURL
	}

	envGiteaAdminAccessToken := os.Getenv("GITEA_ADMIN_ACCESS_TOKEN")
	if len(envGiteaAdminAccessToken) != 0 {
		GiteaAdminAccessToken = envGiteaAdminAccessToken
	}

	envGiteaAdminUsername := os.Getenv("GITEA_ADMIN_USERNAME")
	if len(envGiteaAdminUsername) != 0 {
		GiteaAdminUsername = envGiteaAdminUsername
	}
}
