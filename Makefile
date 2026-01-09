.PHONY: help install dev-setup sync lock run test test-cov lint lint-fix \
		format format-check type-check check-all start stop restart status \
		docker-install clean web-install web-dev web-build web-format web-check

# ══════════════════════════════════════════════════════════════════════════════
# Variables
# ══════════════════════════════════════════════════════════════════════════════
PYTHON_VERSION ?= 3.11

# Docker Compose files
COMPOSE_FILE_PROD = docker-compose.yml
COMPOSE_FILE_DEV = docker-compose.dev.yml

# Docker Compose command shortcuts
DOCKER_COMPOSE_PROD = docker-compose -f $(COMPOSE_FILE_PROD)
DOCKER_COMPOSE_DEV = docker-compose -f $(COMPOSE_FILE_DEV)

# Colors for display
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
CYAN = \033[0;36m
NC = \033[0m

# ══════════════════════════════════════════════════════════════════════════════
##@ Help
# ══════════════════════════════════════════════════════════════════════════════

help: ## Display this help
	@echo ""
	@echo "$(BLUE)╔════════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║              🔒 Vigil Security Scanner                         ║$(NC)"
	@echo "$(BLUE)╚════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make $(CYAN)<target>$(NC)\n\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(CYAN)%-18s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(YELLOW)%s$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(YELLOW)Quick Start:$(NC)"
	@echo "  make dev-setup              # First-time setup (API + Web)"
	@echo "  make dev-up                 # Start dev environment with hot-reload"
	@echo "  make start                  # Start production environment"
	@echo "  open http://localhost:3000  # Access web interface"
	@echo "  open http://localhost:8000/docs # API documentation"
	@echo ""
	@echo "$(YELLOW)Development:$(NC)"
	@echo "  make dev-up                 # Start dev environment (hot-reload)"
	@echo "  make dev-down               # Stop dev environment"
	@echo "  make dev-logs               # View dev logs"
	@echo "  make sync                   # Update API dependencies"
	@echo "  make test                   # Run API tests"
	@echo "  make check-all              # Run all code quality checks"
	@echo ""
	@echo "$(YELLOW)Endpoints:$(NC)"
	@echo "  Web UI:       http://localhost:3000"
	@echo "  API:          http://localhost:8000"
	@echo "  API Docs:     http://localhost:8000/docs"
	@echo "  API ReDoc:    http://localhost:8000/redoc"
	@echo ""

# ══════════════════════════════════════════════════════════════════════════════
##@ Python Development (uv)
# ══════════════════════════════════════════════════════════════════════════════

dev-setup: ## Complete development environment setup (API + Web)
	@echo "$(GREEN)📦 Setting up development environment...$(NC)"
	@echo "$(CYAN)Setting up Python API...$(NC)"
	@command -v uv >/dev/null 2>&1 || { echo "$(RED)❌ uv not found. Install with: curl -LsSf https://astral.sh/uv/install.sh | sh$(NC)"; exit 1; }
	@uv python install $(PYTHON_VERSION)
	@uv sync --all-extras --dev
	@echo "$(CYAN)Installing web dependencies...$(NC)"
	@command -v bun >/dev/null 2>&1 || { echo "$(RED)❌ Bun not found. Install with: curl -fsSL https://bun.sh/install | bash$(NC)"; exit 1; }
	@cd web && bun install
	@echo "$(GREEN)✅ Development environment ready!$(NC)"
	@echo ""
	@echo "$(YELLOW)Next steps:$(NC)"
	@echo "  make dev-up     # Start dev environment with hot-reload"
	@echo "  make start      # Start production environment"

sync: ## Sync dependencies from pyproject.toml
	@echo "$(GREEN)🔄 Syncing dependencies...$(NC)"
	@uv sync --all-extras --dev

lock: ## Update uv.lock file
	@echo "$(GREEN)🔒 Updating lockfile...$(NC)"
	@uv lock

install: ## Install project dependencies only (no dev deps)
	@echo "$(GREEN)📦 Installing production dependencies...$(NC)"
	@uv sync

run: ## Start FastAPI server with uvicorn
	@echo "$(GREEN)🚀 Starting API server...$(NC)"
	@uv run uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# ══════════════════════════════════════════════════════════════════════════════
##@ Code Quality (uv)
# ══════════════════════════════════════════════════════════════════════════════

test: ## Run tests with pytest
	@echo "$(GREEN)🧪 Running tests...$(NC)"
	@uv run pytest tests/ -v

test-cov: ## Run tests with coverage
	@echo "$(GREEN)🧪 Running tests with coverage...$(NC)"
	@uv run pytest tests/ --cov=api --cov-report=term-missing

lint: ## Run ruff linter
	@echo "$(GREEN)🔍 Running ruff linter...$(NC)"
	@uv run ruff check api/ tests/

lint-fix: ## Fix auto-fixable linting issues
	@echo "$(GREEN)🔧 Fixing linting issues...$(NC)"
	@uv run ruff check --fix api/ tests/

format: ## Format code with ruff
	@echo "$(GREEN)✨ Formatting code...$(NC)"
	@uv run ruff format api/ tests/

format-check: ## Check code formatting without modifying
	@echo "$(GREEN)🔍 Checking code format...$(NC)"
	@uv run ruff format --check api/ tests/

type-check: ## Run type checking with pyright
	@echo "$(GREEN)🔍 Running type checker...$(NC)"
	@uv run pyright api/

check-all: format-check lint type-check ## Run all code quality checks
	@echo "$(GREEN)✅ All checks passed!$(NC)"

# ══════════════════════════════════════════════════════════════════════════════
##@ Docker Management - Production
# ══════════════════════════════════════════════════════════════════════════════

docker-install: ## Install/Update Docker images
	@echo "$(BLUE)📦 Installing Docker images...$(NC)"
	@$(DOCKER_COMPOSE_PROD) pull
	@echo "$(GREEN)✅ Docker images installed$(NC)"

start: ## Start production containers
	@echo "$(BLUE)🐳 Starting production containers...$(NC)"
	@$(DOCKER_COMPOSE_PROD) up -d
	@sleep 3
	@echo "$(GREEN)✅ Containers started$(NC)"
	@echo ""
	@echo "$(YELLOW)Access:$(NC)"
	@echo "  Web:  http://localhost:3000"
	@echo "  API:  http://localhost:8000"
	@echo "  Docs: http://localhost:8000/docs"

stop: ## Stop production containers
	@echo "$(YELLOW)🛑 Stopping production containers...$(NC)"
	@$(DOCKER_COMPOSE_PROD) down
	@echo "$(GREEN)✅ Containers stopped$(NC)"

status: ## Check production container status
	@echo "$(BLUE)📊 Production container status:$(NC)"
	@$(DOCKER_COMPOSE_PROD) ps

restart: stop start ## Restart production containers

logs: ## View production logs
	@$(DOCKER_COMPOSE_PROD) logs -f

build: ## Build production images
	@echo "$(GREEN)🏗️  Building production images...$(NC)"
	@$(DOCKER_COMPOSE_PROD) build
	@echo "$(GREEN)✅ Build complete$(NC)"

# ══════════════════════════════════════════════════════════════════════════════
##@ Docker Management - Development
# ══════════════════════════════════════════════════════════════════════════════

dev-up: ## Start development environment with hot-reload
	@echo "$(BLUE)🐳 Starting development environment...$(NC)"
	@$(DOCKER_COMPOSE_DEV) up -d
	@sleep 3
	@echo "$(GREEN)✅ Development environment started$(NC)"
	@echo ""
	@echo "$(YELLOW)Hot-reload enabled:$(NC)"
	@echo "  • API changes auto-reload"
	@echo "  • Web changes auto-reload"
	@echo ""
	@echo "$(YELLOW)Access:$(NC)"
	@echo "  Web:  http://localhost:3000"
	@echo "  API:  http://localhost:8000"
	@echo "  Docs: http://localhost:8000/docs"
	@echo ""
	@echo "$(CYAN)View logs with: make dev-logs$(NC)"

dev-down: ## Stop development environment
	@echo "$(YELLOW)🛑 Stopping development environment...$(NC)"
	@$(DOCKER_COMPOSE_DEV) down
	@echo "$(GREEN)✅ Development environment stopped$(NC)"

dev-restart: dev-down dev-up ## Restart development environment

dev-status: ## Check development container status
	@echo "$(BLUE)📊 Development container status:$(NC)"
	@$(DOCKER_COMPOSE_DEV) ps

dev-logs: ## View development logs (follow mode)
	@$(DOCKER_COMPOSE_DEV) logs -f

dev-logs-api: ## View API logs only
	@$(DOCKER_COMPOSE_DEV) logs -f api

dev-logs-web: ## View web logs only
	@$(DOCKER_COMPOSE_DEV) logs -f web-dev

dev-build: ## Rebuild development images
	@echo "$(GREEN)🏗️  Rebuilding development images...$(NC)"
	@$(DOCKER_COMPOSE_DEV) build
	@echo "$(GREEN)✅ Build complete$(NC)"

dev-shell-api: ## Open shell in API container
	@$(DOCKER_COMPOSE_DEV) exec api /bin/bash

dev-shell-web: ## Open shell in web container
	@$(DOCKER_COMPOSE_DEV) exec web-dev /bin/sh

# ══════════════════════════════════════════════════════════════════════════════
##@ Web Development - Local (without Docker)
# ══════════════════════════════════════════════════════════════════════════════

web-install: ## Install web dependencies
	@echo "$(GREEN)📦 Installing web dependencies...$(NC)"
	@cd web && bun install
	@echo "$(GREEN)✅ Web dependencies installed$(NC)"

web-dev: ## Start web in local dev mode (requires API running)
	@echo "$(BLUE)🚀 Starting web dev server locally...$(NC)"
	@echo "$(YELLOW)⚠️  Make sure API is running: make run$(NC)"
	@cd web && bun run dev

web-build: ## Build web for production
	@echo "$(GREEN)🏗️  Building web...$(NC)"
	@cd web && bun run build
	@echo "$(GREEN)✅ Web built$(NC)"

web-lint: ## Lint web code
	@echo "$(GREEN)🔍 Linting web code...$(NC)"
	@cd web && bun run lint

web-lint-fix: ## Fix web linting issues
	@echo "$(GREEN)🔧 Fixing web linting issues...$(NC)"
	@cd web && bun run lint:fix

web-format: ## Format web code with oxfmt
	@echo "$(GREEN)✨ Formatting web code...$(NC)"
	@cd web && bun run format

web-format-check: ## Check web code formatting
	@echo "$(GREEN)🔍 Checking web formatting...$(NC)"
	@cd web && bun run format:check

web-check: ## Run all web checks (format, lint, typecheck)
	@echo "$(GREEN)✅ Running all web checks...$(NC)"
	@cd web && bun run check

web-clean: ## Clean web build artifacts
	@echo "$(YELLOW)🧹 Cleaning web build...$(NC)"
	@rm -rf web/dist web/node_modules
	@echo "$(GREEN)✅ Web cleaned$(NC)"

# ══════════════════════════════════════════════════════════════════════════════
##@ Cleanup
# ══════════════════════════════════════════════════════════════════════════════

clean: ## Delete outputs directory
	@echo "$(YELLOW)🧹 Cleaning outputs...$(NC)"
	@rm -rf outputs/*
	@mkdir -p outputs
	@echo "$(GREEN)✅ Outputs cleaned$(NC)"

clean-all: clean web-clean ## Clean everything (outputs + web build)
	@echo "$(GREEN)✅ Complete cleanup done$(NC)"

prune: ## Remove all containers and volumes (DESTRUCTIVE)
	@echo "$(RED)⚠️  This will remove ALL containers and volumes!$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		echo "$(YELLOW)🧹 Pruning Docker resources...$(NC)"; \
		$(DOCKER_COMPOSE_PROD) down -v; \
		$(DOCKER_COMPOSE_DEV) down -v; \
		docker system prune -f; \
		echo "$(GREEN)✅ Cleanup complete$(NC)"; \
	fi

.DEFAULT_GOAL := help
