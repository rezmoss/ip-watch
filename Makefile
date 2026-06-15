VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet fmt e2e docker clean release-check snapshot

build: ## Build the static binary into ./ip-watch
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o ip-watch ./cmd/ip-watch

test: ## Run unit + integration (httptest) tests
	go test ./...

vet: ## go vet
	go vet ./...

fmt: ## Check formatting
	@test -z "$$(gofmt -l $$(find . -name '*.go' -not -path '*/vendor/*'))" || (gofmt -l . && exit 1)

e2e: ## Run the Docker-based end-to-end suite (requires Docker; firewall tests need --privileged)
	./test/e2e.sh

docker: ## Build the container image
	docker build -t ip-watch:$(VERSION) .

release-check: ## Validate .goreleaser.yaml
	goreleaser check

snapshot: ## Build a full release locally into ./dist (no publish, no tag needed)
	goreleaser release --snapshot --clean

clean:
	rm -rf ip-watch dist/
