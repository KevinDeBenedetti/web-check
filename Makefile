.PHONY: help install dev-setup sync lock run test test-cov lint lint-fix \
		format format-check type-check check-all start stop restart status \
		docker-install clean

# ══════════════════════════════════════════════════════════════════════════════
# Variables
# ══════════════════════════════════════════════════════════════════════════════
PYTHON_VERSION ?= 3.11

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
	@echo "$(BLUE)║              🔒 Vigil Security Scanner API                     ║$(NC)"
	@echo "$(BLUE)╚════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make $(CYAN)<target>$(NC)\n\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(CYAN)%-18s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(YELLOW)%s$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(YELLOW)Quick Start:$(NC)"
	@echo "  make dev-setup              # First-time setup"
	@echo "  make start                  # Start Docker containers"
	@echo "  make run                    # Start API server (http://localhost:8000)"
	@echo ""
	@echo "$(YELLOW)Development:$(NC)"
	@echo "  make sync                   # Update dependencies"
	@echo "  make test                   # Run tests"
	@echo "  make check-all              # Run all code quality checks"
	@echo ""
	@echo "$(YELLOW)API Documentation:$(NC)"
	@echo "  http://localhost:8000/docs  # Swagger UI"
	@echo "  http://localhost:8000/redoc # ReDoc"
	@echo ""

# ══════════════════════════════════════════════════════════════════════════════
##@ Python Development (uv)
# ══════════════════════════════════════════════════════════════════════════════

dev-setup: ## Complete development environment setup
	@echo "$(GREEN)📦 Setting up development environment with uv...$(NC)"
	@command -v uv >/dev/null 2>&1 || { echo "$(RED)❌ uv not found. Install with: curl -LsSf https://astral.sh/uv/install.sh | sh$(NC)"; exit 1; }
	@uv python install $(PYTHON_VERSION)
	@uv sync --all-extras --dev
	@echo "$(GREEN)✅ Development environment ready!$(NC)"
	@echo "$(YELLOW)Run 'make run' to start the API server$(NC)"

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
##@ Docker Management
# ══════════════════════════════════════════════════════════════════════════════

docker-install: ## Install/Update Docker images
	@echo "$(BLUE)📦 Installing Docker images...$(NC)"
	@docker-compose pull
	@echo "$(GREEN)✅ Docker images installed$(NC)"

start: ## Start Docker containers
	@echo "$(BLUE)🐳 Starting containers...$(NC)"
	@docker-compose up -d > /dev/null 2>&1
	@sleep 2
	@echo "$(GREEN)✅ Containers started$(NC)"

stop: ## Stop Docker containers
	@echo "$(YELLOW)🛑 Stopping containers...$(NC)"
	@docker-compose down
	@echo "$(GREEN)✅ Containers stopped$(NC)"

status: ## Check container status
	@echo "$(BLUE)📊 Container status:$(NC)"
	@docker-compose ps

restart: stop start ## Restart containers

clean: ## Delete outputs directory
	@echo "$(YELLOW)🧹 Cleaning outputs...$(NC)"
	@rm -rf outputs/*
	@echo "$(GREEN)✅ Outputs cleaned$(NC)"

.DEFAULT_GOAL := help
