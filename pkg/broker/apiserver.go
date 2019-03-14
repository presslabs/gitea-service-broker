package broker

import (
	"context"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pivotal-cf/brokerapi"
	"github.com/pivotal-cf/brokerapi/auth"
	"github.com/pivotal-cf/brokerapi/middlewares/originating_identity_header"
	logf "github.com/presslabs/controller-util/log"
	"github.com/presslabs/controller-util/log/adapters/lager"
	"go.uber.org/zap"
	"io"
	"io/ioutil"
	"net/http"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/presslabs/gitea-service-broker/pkg/cmd/options"
	"github.com/presslabs/gitea-service-broker/pkg/internal/vendors/gitea"
)

var log = logf.Log.WithName("gitea-service-broker")

type brokerServer struct {
	// nolint: golint
	HTTPServer *http.Server
}

func NewBrokerServer(addr string, giteaClient gitea.Client, mgr manager.Manager) *brokerServer { // nolint: golint
	r := mux.NewRouter()

	r.Path("/healthz").Methods("GET").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Use(loggingMiddleware)

	// s is used for the broker API
	s := r.PathPrefix("/").Subrouter()
	serviceBroker := &giteaServiceBroker{
		Client:      mgr.GetClient(),
		GiteaClient: giteaClient,
	}
	logger := lager.NewZapAdapter("gitea-service-broker", zap.L())
	brokerapi.AttachRoutes(s, serviceBroker, logger)
	brokerCredentials := brokerapi.BrokerCredentials{
		Username: options.Username,
		Password: options.Password,
	}
	authMiddleware := auth.NewWrapper(brokerCredentials.Username, brokerCredentials.Password).Wrap
	s.Use(authMiddleware)
	s.Use(originating_identity_header.AddToContext)

	httpServer := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	return &brokerServer{
		HTTPServer: httpServer,
	}
}

func zapLoggerFormatter(_ io.Writer, params handlers.LogFormatterParams) {
	log.Info(params.URL.String(),
		"status_code", params.StatusCode,
		"size", params.Size,
		"method", params.Request.Method)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return handlers.CustomLoggingHandler(ioutil.Discard, next, zapLoggerFormatter)
}

func (s *brokerServer) Start(stop <-chan struct{}) error { // nolint: golint
	errChan := make(chan error, 1)
	go func() {
		log.Info("Web Server listening", "address", s.HTTPServer.Addr)
		if err := s.HTTPServer.ListenAndServe(); err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	select {
	case <-stop:
		if err := s.HTTPServer.Shutdown(context.TODO()); err != nil {
			log.Error(err, "unable to shutdown HTTP server properly")
		}
	case err := <-errChan:
		return err
	}
	return nil
}
