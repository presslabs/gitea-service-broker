package broker

import (
	"context"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/pivotal-cf/brokerapi"
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

type BrokerServer struct {
	// nolint: golint
	HTTPServer *http.Server
}

func NewBrokerServer(addr string, giteaClient gitea.Client, mgr manager.Manager) *BrokerServer { // nolint: golint
	h := brokerapi.New(
		&GiteaServiceBroker{
			Client:      mgr.GetClient(),
			GiteaClient: giteaClient,
		},
		lager.NewZapAdapter("gitea-service-broker", zap.L()),
		brokerapi.BrokerCredentials{
			Username: options.Username,
			Password: options.Password,
		},
	)
	h.(*mux.Router).Use(loggingMiddleware)

	httpServer := &http.Server{
		Addr:    addr,
		Handler: h,
	}

	return &BrokerServer{
		HTTPServer: httpServer,
	}
}

func ZapLogFormatter(_ io.Writer, params handlers.LogFormatterParams) {
	log.Info(params.URL.String(),
		"status_code", params.StatusCode,
		"size", params.Size,
		"method", params.Request.Method)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return handlers.CustomLoggingHandler(ioutil.Discard, next, ZapLogFormatter)
}

func (s *BrokerServer) Start(stop <-chan struct{}) error { // nolint: golint
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
