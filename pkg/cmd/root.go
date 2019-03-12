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

package cmd

import (
	goflag "flag"
	"fmt"
	"os"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/runtime/signals"

	logf "github.com/presslabs/controller-util/log"
	"github.com/presslabs/gitea-service-broker/pkg/broker"
	"github.com/presslabs/gitea-service-broker/pkg/cmd/options"
)

var cfg *rest.Config
var log logr.Logger

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gsb",
	Short: "Gitea Service Broker",
	Long:  `Service broker for Gitea that can provision repositories and bind deploy keys.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error

		// validate options
		if err = options.Validate(); err != nil {
			return err
		}

		// setup logging
		development := true
		zapLogger := logf.RawZapLoggerTo(os.Stderr, development)
		logf.SetLogger(zapr.NewLogger(zapLogger))
		zap.ReplaceGlobals(zapLogger)

		// configure Kubernetes rest.Client
		if cfg, err = config.GetConfig(); err != nil {
			return err
		}

		return nil
	},
	Run: runAPIServer,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var runAPIServer = func(cmd *cobra.Command, args []string) {
	log = logf.Log.WithName("gsb")
	log.Info("Starting Gitea Service Broker apiserver...")

	// Create a new Cmd to provide shared dependencies and start components
	mgr, err := manager.New(cfg, manager.Options{
		Namespace: options.Namespace,
	})
	if err != nil {
		log.Error(err, "unable to create a new manager")
		os.Exit(1)
	}

	if err := broker.AddToManager(mgr); err != nil {
		log.Error(err, "unable to setup service broker server")
		os.Exit(1)
	}

	// Start the Cmd
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		log.Error(err, "unable to start the manager")
		os.Exit(1)
	}
}

func init() {
	// add options flags
	options.AddToFlagSet(rootCmd.Flags())
	// add goflag flags
	rootCmd.PersistentFlags().AddGoFlagSet(goflag.CommandLine)
	// remove glog inserted flags
	// nolint: gosec
	// we really don't care about these errors
	_ = rootCmd.PersistentFlags().MarkHidden("alsologtostderr")
	_ = rootCmd.PersistentFlags().MarkHidden("log_backtrace_at")
	_ = rootCmd.PersistentFlags().MarkHidden("log_dir")
	_ = rootCmd.PersistentFlags().MarkHidden("logtostderr")
	_ = rootCmd.PersistentFlags().MarkHidden("stderrthreshold")
	_ = rootCmd.PersistentFlags().MarkHidden("v")
	_ = rootCmd.PersistentFlags().MarkHidden("vmodule")
	_ = rootCmd.PersistentFlags().Set("logtostderr", "true")
	_ = rootCmd.PersistentFlags().Set("alsologtostderr", "false")
}
