.PHONY: help install dev run test lint format check start stop restart logs \
		clean clean-all

# ==============================================================================
# Variables
# ==============================================================================
PYTHON_VERSION ?= 3.11

# Colors for display
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
CYAN = \033[0;36m
NC = \033[0m

# ==============================================================================
##@ Help
# ==============================================================================

help: ## Display this help
	@echo ""
	@echo "$(BLUE)╔═══════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║              🔒 Web-Check Security Scanner                     ║$(NC)"
	@echo "$(BLUE)╚═══════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make $(CYAN)<target>$(NC)\n\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(CYAN)%-18s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(YELLOW)%s$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(YELLOW)Quick Start:$(NC)"
	@echo "  1. Copy .env.example to .env"
	@echo "  2. make start              # Start production environment"
	@echo "  3. Open http://localhost:3000"
	@echo ""
	@echo "$(YELLOW)Development:$(NC)"
	@echo "  make dev                   # Start with hot-reload"
	@echo "  make logs                  # View logs"
	@echo "  make stop                  # Stop containers"
	@echo ""

# ==============================================================================
##@ Docker - Quick Start
# ==============================================================================

start: ## Start production environment (web + api + scanners)
	@echo "$(GREEN)🚀 Starting Web-Check in production mode...$(NC)"
	@docker compose --profile prod up -d
	@echo "$(GREEN)✅ Web-Check is ready!$(NC)"
	@echo ""
	@echo "$(CYAN)Access:$(NC)"
	@echo "  Web UI:       http://localhost:3000"
	@echo "  API:          http://localhost:8000"
	@echo "  API Docs:     http://localhost:8000/docs"
	@echo ""

dev: ## Start development environment (hot-reload enabled)
	@echo "$(GREEN)🚀 Starting Web-Check in development mode...$(NC)"
	@docker compose --profile dev up -d
	@echo "$(GREEN)✅ Development environment ready!$(NC)"
	@echo ""
	@echo "$(YELLOW)Hot-reload enabled for web and API$(NC)"
	@echo ""
	@echo "$(CYAN)Access:$(NC)"
	@echo "  Web UI:       http://localhost:3000"
	@echo "  API:          http://localhost:8000"
	@echo "  API Docs:     http://localhost:8000/docs"
	@echo ""
	@echo "$(CYAN)View logs: make logs$(NC)"

stop: ## Stop all containers
	@echo "$(YELLOW)🛑 Stopping Web-Check...$(NC)"
	@docker compose --profile prod --profile dev down
	@echo "$(GREEN)✅ Stopped$(NC)"

restart: stop start ## Restart production environment

logs: ## View logs (all containers)
	@docker compose logs -f

logs-api: ## View API logs only
	@docker compose logs -f api

logs-web: ## View web logs only
	@docker compose --profile prod logs -f web || docker compose --profile dev logs -f web-dev

status: ## Show container status
	@echo "$(BLUE)📊 Container Status:$(NC)"
	@docker compose ps

# ==============================================================================
##@ Development Tools
# ==============================================================================

install: ## Install/setup development environment
	@echo "$(GREEN)📦 Setting up development environment...$(NC)"
	@command -v uv >/dev/null 2>&1 || { echo "$(RED)❌ uv not found. Install: curl -LsSf https://astral.sh/uv/install.sh | sh$(NC)"; exit 1; }
	@command -v bun >/dev/null 2>&1 || { echo "$(RED)❌ Bun not found. Install: curl -fsSL https://bun.sh/install | bash$(NC)"; exit 1; }
	@uv python install $(PYTHON_VERSION)
	@uv sync --all-extras --dev
	@cd web && bun install
	@echo "$(GREEN)✅ Development environment ready!$(NC)"

run: ## Run API locally (outside Docker)
	@echo "$(GREEN)🚀 Starting API locally...$(NC)"
	@uv run uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

test: ## Run tests
	@echo "$(GREEN)🧪 Running tests...$(NC)"
	@uv run pytest api/tests/ -v

lint: ## Lint code
	@echo "$(GREEN)🔍 Linting...$(NC)"
	@uv run ruff check api/

format: ## Format code
	@echo "$(GREEN)✨ Formatting code...$(NC)"
	@uv run ruff format api/

check: ## Run all code quality checks
	@echo "$(GREEN)✅ Running all checks...$(NC)"
	@uv run ruff format --check api/
	@uv run ruff check api/
	@uv run ty check api/
	@echo "$(GREEN)✅ All checks passed!$(NC)"

ci: ## Test all CI workflow steps locally
	@echo "$(BLUE)╔═══════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║           🧪 Running CI Workflow Locally                      ║$(NC)"
	@echo "$(BLUE)╚═══════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(YELLOW)📋 Step 1/11: Gitleaks Secret Scan$(NC)"
	@command -v gitleaks >/dev/null 2>&1 || { echo "$(YELLOW)⚠️  Gitleaks not installed. Install: brew install gitleaks$(NC)"; }
	@command -v gitleaks >/dev/null 2>&1 && gitleaks detect --no-banner --verbose || echo "$(YELLOW)⏭️  Skipped (gitleaks not installed)$(NC)"
	@echo ""
	@echo "$(YELLOW)📋 Step 2/11: Python Lint (Ruff)$(NC)"
	@uv run ruff check --output-format=github --target-version=py312 api/
	@echo "$(GREEN)✅ Python lint passed$(NC)"
	@echo ""
	@echo "$(YELLOW)📋 Step 3/11: Python Format Check (Ruff)$(NC)"
	@uv run ruff format --check --target-version=py312 api/
	@echo "$(GREEN)✅ Python format check passed$(NC)"
	@echo ""
	@echo "$(YELLOW)📋 Step 4/11: Python Type Check (ty)$(NC)"
	@uv run ty check api/
	@echo "$(GREEN)✅ Python type check passed$(NC)"
	@echo ""
	@echo "$(YELLOW)📋 Step 5/11: Python Tests (Pytest)$(NC)"
	@uv run pytest api/tests/ --cov=api --cov-report=term-missing -v
	@echo "$(GREEN)✅ Python tests passed$(NC)"
	@echo ""
	@echo "$(YELLOW)📋 Step 6/11: Python Build (Docker)$(NC)"
	@docker buildx build -t web-check:test -f Dockerfile . --load
	@echo "$(GREEN)✅ Python Docker build passed$(NC)"
	@echo ""
	@echo "$(YELLOW)📋 Step 7/11: React Lint (oxlint)$(NC)"
	@cd web && bun run lint
	@echo "$(GREEN)✅ React lint passed$(NC)"
	@echo ""
	@echo "$(YELLOW)📋 Step 8/11: React Format Check (oxfmt)$(NC)"
	@cd web && bun run format:check
	@echo "$(GREEN)✅ React format check passed$(NC)"
	@echo ""
	@echo "$(YELLOW)📋 Step 9/11: React Type Check (TypeScript)$(NC)"
	@cd web && bun run tsc --noEmit
	@echo "$(GREEN)✅ React type check passed$(NC)"
	@echo ""
	@echo "$(YELLOW)📋 Step 10/11: React Build (Vite)$(NC)"
	@cd web && bun run build
	@echo "$(GREEN)✅ React build passed$(NC)"
	@echo ""
	@echo "$(YELLOW)📋 Step 11/11: React Build (Docker)$(NC)"
	@docker buildx build -t web-check-ui:test -f web/Dockerfile web/ --load
	@echo "$(GREEN)✅ React Docker build passed$(NC)"
	@echo ""
	@echo "$(BLUE)╔═══════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║           $(GREEN)✅ All CI Checks Passed Successfully!$(BLUE)             ║$(NC)"
	@echo "$(BLUE)╚═══════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""

# ==============================================================================
##@ Cleanup
# ==============================================================================

clean: ## Clean output files
	@echo "$(YELLOW)🧹 Cleaning outputs...$(NC)"
	@rm -rf outputs/*
	@mkdir -p outputs
	@echo "$(GREEN)✅ Outputs cleaned$(NC)"

clean-all: ## Remove all containers, volumes, and outputs
	@echo "$(RED)⚠️  This will remove ALL containers, volumes, and outputs!$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		echo "$(YELLOW)🧹 Cleaning everything...$(NC)"; \
		docker compose --profile prod --profile dev down -v; \
		docker system prune -f; \
		rm -rf outputs/*; \
		rm -rf web/dist web/node_modules; \
		echo "$(GREEN)✅ Complete cleanup done$(NC)"; \
	fi

.DEFAULT_GOAL := help
