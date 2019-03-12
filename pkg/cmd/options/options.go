package options

import (
	"errors"
	"net/url"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	// ServiceID is the ID of the service
	ServiceID = "b431cc67-89fa-4f4a-8b1b-8f8a70c71b5e"
	// ServiceName is the name of the service
	ServiceName = "gitea-repository"
	// DefaultPlanID is the ID of the plan
	DefaultPlanID = "3034df5d-c976-4265-87fd-7d3cfbe54a79"
	// DefaultPlanName is the name of the default plan
	DefaultPlanName = "default"
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
	flag.String("service-id", ServiceID, "Service ID")
	flag.String("service-name", ServiceName, "Service Name")
	flag.String("default-plan-id", DefaultPlanID, "Default Plan ID")
	flag.String("default-plan-name", DefaultPlanName, "Default Plan Name")
	flag.String("username", "", "Service broker http username")
	flag.String("password", "", "Service broker http password")
	flag.String("gitea-url", GiteaURL, "Gitea URL")
	flag.String("gitea-access-token", GiteaAdminAccessToken, "Token for accessing Gitea")
	flag.String("gitea-admin-username", GiteaAdminUsername, "User to be used for Gitea admin operations")
	flag.String("namespace", Namespace, "Namespace where objects such as secrets will be created")
	flag.Float64("operation-timeout", OperationTimeout, "Number of seconds after which an unfinished operation is failed")

}

// LoadFromViper loads and validates the arguments
func LoadFromViper() error {
	Username = viper.GetString("username")
	if Username == "" {
		return errors.New("You must specify username")
	}

	Password = viper.GetString("password")
	if Password == "" {
		return errors.New("You must specify password")
	}

	GiteaURL = viper.GetString("gitea-url")
	if GiteaURL == "" {
		return errors.New("You must specify gitea-url")
	}
	_, err := url.Parse(GiteaURL)
	if err != nil {
		return err
	}

	GiteaAdminAccessToken = viper.GetString("gitea-access-token")
	if GiteaAdminAccessToken == "" {
		return errors.New("You must specify gitea-access-token")
	}

	GiteaAdminUsername = viper.GetString("gitea-admin-username")
	if GiteaAdminUsername == "" {
		return errors.New("You must specify gitea-admin-username")
	}

	ServiceID = viper.GetString("service-id")
	ServiceName = viper.GetString("service-name")
	DefaultPlanID = viper.GetString("default-plan-id")
	DefaultPlanName = viper.GetString("default-plan-name")
	Namespace = viper.GetString("namespace")
	OperationTimeout = viper.GetFloat64("operation-timeout")
	return nil
}
