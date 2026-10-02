# DƏLİL developer tasks. Run `make help`.
SHELL := /bin/bash
VERSION ?= 0.1.0
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X github.com/serxan22/delil/internal/version.Version=$(VERSION) -X github.com/serxan22/delil/internal/version.Commit=$(COMMIT)
COMPOSE ?= docker compose

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-18s\033[0m %s\n", $$1, $$2}'

.env:
	cp .env.example .env

.PHONY: dev
dev: .env ## Start Postgres, API and dashboard with Docker Compose
	$(COMPOSE) up --build

.PHONY: down
down: ## Stop the stack (keeps data)
	$(COMPOSE) down

.PHONY: reset
reset: ## Stop the stack and DELETE all local data
	$(COMPOSE) down -v

.PHONY: credentials
credentials: ## Show the bootstrap credentials printed by the API on first start
	@$(COMPOSE) logs api | grep -A10 "bootstrap complete" || echo "No bootstrap banner found (already bootstrapped?)"

.PHONY: build
build: ## Build delil-server and delil into ./bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/delil-server ./cmd/delil-server
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/delil ./cmd/delil

.PHONY: test
test: ## Unit tests (Go, SDK, dashboard); database tests skip without DELIL_TEST_DATABASE_URL
	go test -short ./...
	cd sdk/typescript && npm test
	cd apps/dashboard && npm test

.PHONY: test-integration
test-integration: ## Go tests against PostgreSQL (needs DELIL_TEST_DATABASE_URL)
	@test -n "$$DELIL_TEST_DATABASE_URL" || (echo "set DELIL_TEST_DATABASE_URL, e.g. postgres://delil:...@127.0.0.1:5432/postgres?sslmode=disable" && exit 1)
	go test -race -count=1 ./...

.PHONY: test-vectors
test-vectors: ## Check the published test vectors with an independent Node.js implementation
	go test ./pkg/integrity -run TestKnownAnswerVectors
	node scripts/verify-test-vectors.mjs

.PHONY: lint
lint: ## Lint Go, the SDK and the dashboard
	golangci-lint run ./...
	cd sdk/typescript && npm run typecheck
	cd apps/dashboard && npm run lint && npm run typecheck

.PHONY: fmt
fmt: ## Format Go code
	gofmt -w cmd internal pkg api migrations

.PHONY: migrate
migrate: ## Apply migrations (uses DELIL_MIGRATION_DATABASE_URL or DELIL_DATABASE_URL)
	go run ./cmd/delil-server migrate

.PHONY: seed
seed: ## Seed demo data into a project: make seed PROJECT=<id-or-slug>
	go run ./cmd/delil-server demo seed --project $(PROJECT)

.PHONY: verify
verify: ## Verify every stream independently with the CLI (needs DELIL_API_KEY)
	go run ./cmd/delil verify

.PHONY: tamper-demo
tamper-demo: ## Tamper with one event in the Compose database and watch verification fail
	./scripts/tamper-demo.sh

.PHONY: benchmark
benchmark: ## Run engine benchmarks and the ingestion/verification load test
	go test -run '^$$' -bench . -benchmem ./pkg/...
	go run ./cmd/delil-bench

.PHONY: openapi-lint
openapi-lint: ## Lint the OpenAPI document
	npx --yes @redocly/cli@2.12.0 lint api/openapi.yaml

.PHONY: secrets-scan
secrets-scan: ## Scan the repository history for secrets
	gitleaks git --redact --no-banner .

.PHONY: clean
clean: ## Remove build output
	rm -rf bin sdk/typescript/dist apps/dashboard/.next
