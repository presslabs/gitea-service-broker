/*
Copyright 2018 Pressinfra SRL.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package broker

import (
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	logf "github.com/presslabs/controller-util/log"
	"sigs.k8s.io/testing_frameworks/integration/addr"

	"github.com/presslabs/gitea-service-broker/pkg/internal/vendors/gitea"
)

var cfg *rest.Config
var t *envtest.Environment

func TestProjectController(t *testing.T) {
	logf.SetLogger(logf.ZapLoggerTo(GinkgoWriter, true))
	RegisterFailHandler(Fail)
	RunSpecsWithDefaultAndCustomReporters(t, "Project Controller Suite", []Reporter{envtest.NewlineReporter{}})
}

var _ = BeforeSuite(func() {
	var err error
	t = &envtest.Environment{
		ControlPlaneStartTimeout: 30 * time.Second,
	}

	cfg, err = t.Start()
	Expect(err).NotTo(HaveOccurred())
})

var _ = AfterSuite(func() {
	t.Stop()
})

func SetupAPIServer(giteaClient gitea.Client, mgr manager.Manager) *BrokerServer {
	httpPort, _, err := addr.Suggest()
	Expect(err).To(Succeed())

	server := NewBrokerServer(fmt.Sprintf(":%d", httpPort), giteaClient, mgr)
	err = mgr.Add(server)
	Expect(err).To(Succeed())

	return server
}

// StartTestManager adds recFn
func StartTestManager(mgr manager.Manager) chan struct{} {
	stop := make(chan struct{})
	go func() {
		Expect(mgr.Start(stop)).To(Succeed())
	}()
	return stop
}
