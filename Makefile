#===============================================================================
#
#          FILE: Makefile
#
#   DESCRIPTION: MR-X VPN Panel Build Commands
#
#        AUTHOR: MR-X Team
#       VERSION: 1.0.0
#
#===============================================================================

# Variables
APP_NAME := Mxui
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "1.0.0")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GO_VERSION := $(shell go version | cut -d' ' -f3)

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := gofmt
GOVET := $(GOCMD) vet
GOLINT := golangci-lint

# Directories
SRC_DIR := ./cmd
CORE_DIR := ./Core
WEB_DIR := ./Web
BUILD_DIR := ./build
DIST_DIR := ./dist
BIN_DIR := ./bin

# Build flags
LDFLAGS := -ldflags "-s -w \
	-X 'main.Version=$(VERSION)' \
	-X 'main.BuildTime=$(BUILD_TIME)' \
	-X 'main.GitCommit=$(GIT_COMMIT)' \
	-X 'main.GoVersion=$(GO_VERSION)'"

# CGO settings
CGO_ENABLED := 0

# Target platforms
PLATFORMS := linux/amd64 linux/arm64 linux/armv7 darwin/amd64 darwin/arm64 windows/amd64

# Docker settings
DOCKER_IMAGE := ghcr.io/mr-x-panel/Mxui
DOCKER_TAG := $(VERSION)

#===============================================================================
# Default target
#===============================================================================
.PHONY: all
all: clean deps build

#===============================================================================
# Help
#===============================================================================
.PHONY: help
help:
	@echo ""
	@echo "MR-X VPN Panel - Build System"
	@echo "=============================="
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Clean, install deps, and build"
	@echo "  build        - Build for current platform"
	@echo "  build-all    - Build for all platforms"
	@echo "  build-linux  - Build for Linux (amd64, arm64, armv7)"
	@echo "  build-darwin - Build for macOS (amd64, arm64)"
	@echo "  build-windows- Build for Windows (amd64)"
	@echo "  clean        - Clean build artifacts"
	@echo "  deps         - Install dependencies"
	@echo "  test         - Run tests"
	@echo "  test-cover   - Run tests with coverage"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo "  vet          - Run go vet"
	@echo "  docker       - Build Docker image"
	@echo "  docker-push  - Push Docker image"
	@echo "  release      - Create release package"
	@echo "  install      - Install locally"
	@echo "  run          - Run development server"
	@echo "  dev          - Run with hot reload"
	@echo ""

#===============================================================================
# Dependencies
#===============================================================================
.PHONY: deps
deps:
	@echo "📦 Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "✅ Dependencies installed"

.PHONY: deps-update
deps-update:
	@echo "🔄 Updating dependencies..."
	$(GOGET) -u ./...
	$(GOMOD) tidy
	@echo "✅ Dependencies updated"

#===============================================================================
# Build
#===============================================================================
.PHONY: build
build: deps
	@echo "🔨 Building $(APP_NAME) $(VERSION)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME) $(SRC_DIR)/main.go
	@echo "✅ Build complete: $(BIN_DIR)/$(APP_NAME)"

.PHONY: build-debug
build-debug: deps
	@echo "🔨 Building $(APP_NAME) (debug)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GOBUILD) -gcflags="all=-N -l" -o $(BIN_DIR)/$(APP_NAME)-debug $(SRC_DIR)/main.go
	@echo "✅ Debug build complete"

.PHONY: build-all
build-all: clean deps
	@echo "🔨 Building for all platforms..."
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} \
		CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) \
		-o $(DIST_DIR)/$(APP_NAME)-$${platform%/*}-$${platform#*/}$(if $(findstring windows,$${platform%/*}),.exe,) \
		$(SRC_DIR)/main.go || exit 1; \
		echo "  ✅ Built: $(APP_NAME)-$${platform%/*}-$${platform#*/}"; \
	done
	@echo "✅ All platforms built"

.PHONY: build-linux
build-linux: deps
	@echo "🔨 Building for Linux..."
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-linux-amd64 $(SRC_DIR)/main.go
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-linux-arm64 $(SRC_DIR)/main.go
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-linux-armv7 $(SRC_DIR)/main.go
	@echo "✅ Linux builds complete"

.PHONY: build-darwin
build-darwin: deps
	@echo "🔨 Building for macOS..."
	@mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-darwin-amd64 $(SRC_DIR)/main.go
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-darwin-arm64 $(SRC_DIR)/main.go
	@echo "✅ macOS builds complete"

.PHONY: build-windows
build-windows: deps
	@echo "🔨 Building for Windows..."
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-windows-amd64.exe $(SRC_DIR)/main.go
	@echo "✅ Windows build complete"

#===============================================================================
# Testing
#===============================================================================
.PHONY: test
test:
	@echo "🧪 Running tests..."
	$(GOTEST) -v -race ./...
	@echo "✅ Tests passed"

.PHONY: test-short
test-short:
	@echo "🧪 Running short tests..."
	$(GOTEST) -v -short ./...
	@echo "✅ Short tests passed"

.PHONY: test-cover
test-cover:
	@echo "🧪 Running tests with coverage..."
	@mkdir -p $(BUILD_DIR)
	$(GOTEST) -v -race -coverprofile=$(BUILD_DIR)/coverage.out ./...
	$(GOCMD) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "✅ Coverage report: $(BUILD_DIR)/coverage.html"

.PHONY: test-bench
test-bench:
	@echo "🧪 Running benchmarks..."
	$(GOTEST) -v -bench=. -benchmem ./...
	@echo "✅ Benchmarks complete"

#===============================================================================
# Code Quality
#===============================================================================
.PHONY: lint
lint:
	@echo "🔍 Running linter..."
	@if command -v $(GOLINT) > /dev/null; then \
		$(GOLINT) run ./...; \
	else \
		echo "⚠️  golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi
	@echo "✅ Lint complete"

.PHONY: fmt
fmt:
	@echo "📝 Formatting code..."
	$(GOFMT) -s -w $(SRC_DIR)
	@echo "✅ Code formatted"

.PHONY: fmt-check
fmt-check:
	@echo "📝 Checking code format..."
	@test -z "$$($(GOFMT) -l $(SRC_DIR))" || (echo "❌ Code not formatted" && exit 1)
	@echo "✅ Code format OK"

.PHONY: vet
vet:
	@echo "🔍 Running go vet..."
	$(GOVET) ./...
	@echo "✅ Vet complete"

.PHONY: check
check: fmt-check vet lint test
	@echo "✅ All checks passed"

#===============================================================================
# Docker
#===============================================================================
.PHONY: docker
docker:
	@echo "🐳 Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest
	@echo "✅ Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)"

.PHONY: docker-push
docker-push: docker
	@echo "🐳 Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_IMAGE):latest
	@echo "✅ Docker image pushed"

.PHONY: docker-run
docker-run:
	@echo "🐳 Running Docker container..."
	docker run -d \
		--name $(APP_NAME) \
		--network host \
		-v Mxui_data:/app/data \
		-v Mxui_logs:/app/logs \
		$(DOCKER_IMAGE):$(DOCKER_TAG)
	@echo "✅ Container started"

.PHONY: docker-stop
docker-stop:
	@echo "🐳 Stopping Docker container..."
	docker stop $(APP_NAME) || true
	docker rm $(APP_NAME) || true
	@echo "✅ Container stopped"

.PHONY: docker-compose-up
docker-compose-up:
	@echo "🐳 Starting with Docker Compose..."
	docker compose up -d
	@echo "✅ Services started"

.PHONY: docker-compose-down
docker-compose-down:
	@echo "🐳 Stopping Docker Compose..."
	docker compose down
	@echo "✅ Services stopped"

#===============================================================================
# Release
#===============================================================================
.PHONY: release
release: clean build-all
	@echo "📦 Creating release package..."
	@mkdir -p $(DIST_DIR)/release
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		binary=$(APP_NAME)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then binary=$$binary.exe; fi; \
		cp $(DIST_DIR)/$$binary $(DIST_DIR)/release/; \
	done
	@cp -r $(WEB_DIR) $(DIST_DIR)/release/web
	@cp config.yaml $(DIST_DIR)/release/
	@cp README.md $(DIST_DIR)/release/
	@cp LICENSE $(DIST_DIR)/release/
	@tar -czf $(DIST_DIR)/$(APP_NAME)-$(VERSION).tar.gz -C $(DIST_DIR)/release .
	@cd $(DIST_DIR)/release && zip -r ../$(APP_NAME)-$(VERSION).zip .
	@echo "✅ Release packages created"

.PHONY: release-web
release-web:
	@echo "📦 Creating web assets package..."
	@mkdir -p $(DIST_DIR)
	@tar -czf $(DIST_DIR)/web.tar.gz -C $(WEB_DIR) .
	@echo "✅ Web package created: $(DIST_DIR)/web.tar.gz"

#===============================================================================
# Installation
#===============================================================================
.PHONY: install
install: build
	@echo "📥 Installing $(APP_NAME)..."
	@sudo mkdir -p /opt/Mxui/{bin,data,logs,web,certs,backups}
	@sudo cp $(BIN_DIR)/$(APP_NAME) /opt/Mxui/bin/
	@sudo cp -r $(WEB_DIR)/* /opt/Mxui/web/
	@sudo cp config.yaml /opt/Mxui/
	@sudo cp Mxui.service /etc/systemd/system/
	@sudo systemctl daemon-reload
	@echo "✅ Installation complete"
	@echo "   Run: sudo systemctl enable --now Mxui"

.PHONY: uninstall
uninstall:
	@echo "📤 Uninstalling $(APP_NAME)..."
	@sudo systemctl stop Mxui || true
	@sudo systemctl disable Mxui || true
	@sudo rm -f /etc/systemd/system/Mxui.service
	@sudo systemctl daemon-reload
	@echo "⚠️  Data directory /opt/Mxui NOT removed. Remove manually if needed."
	@echo "✅ Uninstall complete"

#===============================================================================
# Development
#===============================================================================
.PHONY: run
run: build
	@echo "🚀 Running $(APP_NAME)..."
	$(BIN_DIR)/$(APP_NAME) serve --config config.yaml

.PHONY: dev
dev:
	@echo "🔄 Running with hot reload..."
	@if command -v air > /dev/null; then \
		air; \
	else \
		echo "⚠️  Air not installed. Install with: go install github.com/cosmtrek/air@latest"; \
		$(MAKE) run; \
	fi

.PHONY: dev-web
dev-web:
	@echo "🌐 Running web development server..."
	@cd $(WEB_DIR) && python3 -m http.server 8080

#===============================================================================
# Database
#===============================================================================
.PHONY: db-migrate
db-migrate:
	@echo "🔄 Running database migrations..."
	$(BIN_DIR)/$(APP_NAME) migrate up
	@echo "✅ Migrations complete"

.PHONY: db-rollback
db-rollback:
	@echo "🔄 Rolling back database..."
	$(BIN_DIR)/$(APP_NAME) migrate down
	@echo "✅ Rollback complete"

.PHONY: db-reset
db-reset:
	@echo "🔄 Resetting database..."
	$(BIN_DIR)/$(APP_NAME) migrate reset
	@echo "✅ Database reset"

#===============================================================================
# Clean
#===============================================================================
.PHONY: clean
clean:
	@echo "🧹 Cleaning..."
	$(GOCLEAN)
	@rm -rf $(BIN_DIR) $(BUILD_DIR) $(DIST_DIR)
	@rm -f coverage.out coverage.html
	@echo "✅ Clean complete"

.PHONY: clean-all
clean-all: clean
	@echo "🧹 Deep cleaning..."
	$(GOCLEAN) -cache -testcache -modcache
	@echo "✅ Deep clean complete"

#===============================================================================
# Utilities
#===============================================================================
.PHONY: version
version:
	@echo "Version:    $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Go Version: $(GO_VERSION)"

.PHONY: tools
tools:
	@echo "📦 Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/cosmtrek/air@latest
	go install github.com/swaggo/swag/cmd/swag@latest
	@echo "✅ Tools installed"

.PHONY: generate
generate:
	@echo "🔄 Generating code..."
	$(GOCMD) generate ./...
	@echo "✅ Generation complete"

.PHONY: swagger
swagger:
	@echo "📄 Generating Swagger docs..."
	@if command -v swag > /dev/null; then \
		swag init -g $(SRC_DIR)/main.go -o ./docs; \
	else \
		echo "⚠️  Swag not installed. Install with: go install github.com/swaggo/swag/cmd/swag@latest"; \
	fi
	@echo "✅ Swagger docs generated"

# Ensure bin directory exists
$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Ensure dist directory exists
$(DIST_DIR):
	@mkdir -p $(DIST_DIR)
