package broker

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pivotal-cf/brokerapi"
	logf "github.com/presslabs/controller-util/log"
	"github.com/presslabs/controller-util/log/adapters/lager"
	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/presslabs/gitea-service-broker/pkg/cmd/options"
	"github.com/presslabs/gitea-service-broker/pkg/internal/vendors/gitea"
)

var log = logf.Log.WithName("gitea-service-broker")

type BrokerServer struct { // nolint: golint
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

	broker := &BrokerServer{}

	httpServer := &http.Server{
		Addr:    addr,
		Handler: broker.Log(h.ServeHTTP),
	}

	return &BrokerServer{
		HTTPServer: httpServer,
	}
}

func (s *BrokerServer) Log(h http.HandlerFunc) http.HandlerFunc { // nolint: golint
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf(">>>>>>>>>>>>>>>>>>> %#v\n", r)
		h(w, r)
	}
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
