BUILDDIR?=$(CURDIR)/build
KMS_OUTPUT ?= $(BUILDDIR)/kms
KMS_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
KMS_LDFLAGS := -X github.com/cosmos/kms/internal/version.Version=$(KMS_VERSION)
KMS_BUILD_FLAGS := -mod=readonly -ldflags "$(KMS_LDFLAGS)"
KMS_COVERPROFILE ?= $(BUILDDIR)/coverage.out
KMS_COVERHTML ?= $(BUILDDIR)/coverage.html

#? build: Build kms into $(BUILDDIR)
build:
	CGO_ENABLED=1 go build $(KMS_BUILD_FLAGS) -o $(KMS_OUTPUT) ./cmd/kms
.PHONY: build

#? install: Install kms to GOBIN
install:
	CGO_ENABLED=1 go install $(KMS_BUILD_FLAGS) ./cmd/kms
.PHONY: install

#? test: Run the kms test suite
test:
	CGO_ENABLED=1 go test ./... -count=1
.PHONY: test

#? test-race: Run the kms test suite with the race detector
test-race:
	CGO_ENABLED=1 go test ./... -race -count=1
.PHONY: test-race

#? test-localstack: Run the kms LocalStack integration tests (requires a running LocalStack KMS; skips if unreachable)
test-localstack:
	CGO_ENABLED=1 go test -tags localstack ./... -count=1 -run LocalStack -v
.PHONY: test-localstack

#? cover: Run kms tests with coverage; write profile + HTML to $(BUILDDIR) and print the total
cover:
	@mkdir -p $(BUILDDIR)
	go test ./... -covermode=atomic -coverpkg=./... -coverprofile=$(KMS_COVERPROFILE) -count=1
	go tool cover -func=$(KMS_COVERPROFILE) | tail -n 1
	go tool cover -html=$(KMS_COVERPROFILE) -o $(KMS_COVERHTML)
	@echo "coverage profile: $(KMS_COVERPROFILE)"
	@echo "coverage html:    $(KMS_COVERHTML)"
.PHONY: cover

#? vet: Vet the kms module
vet:
	CGO_ENABLED=1 go vet ./...
.PHONY: vet

#? lint: Lint the kms module (pinned golangci-lint)
lint:
	CGO_ENABLED=1 go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.3 run
.PHONY: lint

#? lint-fix: Lint the kms module (pinned golangci-lint) with --fix flag
lint-fix:
	CGO_ENABLED=1 go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.3 run --fix
.PHONY: lint

#? tidy: Tidy the kms module dependencies
tidy:
	go mod tidy
.PHONY: tidy

#? proto-gen: Generate protobuf types
proto-gen:
	protoc \
	  --go_out=gen --go_opt=paths=source_relative \
	  --go-grpc_out=gen --go-grpc_opt=paths=source_relative \
	  --proto_path=proto \
	  proto/signerservice/signerservice.proto
.PHONY: proto-gen

#? clean: Remove kms build and coverage artifacts
clean:
	rm -f $(KMS_OUTPUT) $(KMS_COVERPROFILE) $(KMS_COVERHTML)
.PHONY: clean
