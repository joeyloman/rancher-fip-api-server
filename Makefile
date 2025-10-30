# Image URL to use all building/pushing image targets
IMG ?= your-repo/rancher-fip-api-server:latest
# Produce CRDs that work back to Kubernetes 1.11 (no pruning).
CRD_OPTIONS ?= "crd:trivialVersions=true,preserveUnknownFields=false"

all: manager

# =================================================================================================
# Development
# =================================================================================================

## Run manager binary against the cluster specified in ~/.kube/config
run: generate
	go run ./cmd/api-server/main.go --leader-elect=true  --listen-address=:8080 --tls-enabled=false

## Run tests
test: generate
	go test -v ./pkg/... ./cmd/... ./internal/...

# =================================================================================================
# Build
# =================================================================================================

## Build manager binary
manager: generate
	go build -o bin/rancher-fip-api-server cmd/api-server/main.go

## Build the docker image
docker-build: test
	docker build -f Dockerfile -t ${IMG} .

## Push the docker image
docker-push:
	docker push ${IMG}

# =================================================================================================
# Deployment
# =================================================================================================

## Deploy controller to the cluster
deploy:
	kubectl apply -f deployments/deployment.yaml

## Undeploy controller from the cluster
undeploy:
	kubectl delete -f deployments/deployment.yaml

.PHONY: all run test manager docker-build docker-push generate deploy undeploy
