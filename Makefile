# Image URL to use all building/pushing image targets
APP_VERSION      ?= $(shell git describe --abbrev=5 --dirty --tags --always)
REGISTRY         := quay.io/presslabs
IMAGE_NAME       := gitea-service-broker
BUILD_TAG        := build
IMAGE_TAGS       := $(APP_VERSION)
BINDIR           ?= $(CURDIR)/bin
CHARTDIR         ?= $(CURDIR)/charts/gitea-service-broker

GOOS ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')
GOARCH ?= amd64

PATH := $(BINDIR):$(PATH)
SHELL := env 'PATH=$(PATH)' /bin/sh

# Run tests
test: generate manifests
	$(BINDIR)/ginkgo \
		--randomizeAllSpecs --randomizeSuites --failOnPending \
		--cover --coverprofile cover.out --trace --race -v \
		./pkg/... ./cmd/...

# Build manager binary
manager: generate fmt vet
	go build -o bin/manager github.com/presslabs/gitea-service-broker/cmd/manager

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet
	go run ./cmd/manager/main.go

# Install CRDs into a cluster
install: manifests
	kubectl apply -f config/crds

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests
	kubectl apply -f config/crds
	kustomize build config/default | kubectl apply -f -

# Generate manifests e.g. CRD, RBAC etc.
manifests:
	go run vendor/sigs.k8s.io/controller-tools/cmd/controller-gen/main.go all

# Run go fmt against code
fmt:
	go fmt ./pkg/... ./cmd/...

# Run go vet against code
vet:
	go vet ./pkg/... ./cmd/...

# Generate code
generate:
	go generate ./pkg/... ./cmd/...

# Build the docker image
docker-build: vendor
	docker build . -t ${IMG}
	@echo "updating kustomize image patch file for manager resource"
	sed -i'' -e 's@image: .*@image: '"${IMG}"'@' ./config/default/manager_image_patch.yaml

# Push the docker image
docker-push:
	docker push ${IMG}

.PHONY: lint
lint:
	$(BINDIR)/golangci-lint run ./pkg/... ./cmd/...

.PHONY: chart
chart:
	yq w -i $(CHARTDIR)/Chart.yaml version "$(APP_VERSION)"
	yq w -i $(CHARTDIR)/Chart.yaml appVersion "$(APP_VERSION)"
	mv $(CHARTDIR)/values.yaml $(CHARTDIR)/_values.yaml
	sed 's#$(REGISTRY)/$(IMAGE_NAME):latest#$(REGISTRY)/$(IMAGE_NAME):$(APP_VERSION)#g' $(CHARTDIR)/_values.yaml > $(CHARTDIR)/values.yaml
	rm $(CHARTDIR)/_values.yaml

dependencies:
	test -d $(BINDIR) || mkdir $(BINDIR)
	GOBIN=$(BINDIR) go install ./vendor/github.com/onsi/ginkgo/ginkgo
	curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | bash -s -- -b $(BINDIR) v1.10.2
