ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
IMG ?= audit-scanner:latest
## Location to install dependencies to
BIN_DIR ?=  $(abspath $(ROOT_DIR)/bin)
GOLANGCI_LINT_VER ?= v1.64.5
GOLANGCI_LINT := $(BIN_DIR)/golangci-lint-$(GOLANGCI_LINT_VER)

all: build

$(GOLANGCI_LINT): 
	GOBIN=$(BIN_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VER)
	mv $(BIN_DIR)/golangci-lint $(GOLANGCI_LINT)

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.

fmt: ## Run go fmt against code.
	go fmt ./...

vet: ## Run go vet against code.
	go vet -tags=testing ./... 

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run

.PHONY: unit-tests
unit-tests: fmt vet ## Run unit tests.
	go test ./... -tags=testing -race -test.v -coverprofile=coverage/unit-tests/coverage.txt -covermode=atomic 

.PHONY: build
build: fmt vet lint ## Build audit-scanner binary.
	CGO_ENABLED=0 GOOS=linux GO111MODULE=on go build -a -o $(BIN_DIR)/audit-scanner .

.PHONY: docker-build
docker-build: unit-tests
	DOCKER_BUILDKIT=1 docker build -t ${IMG} .
	
