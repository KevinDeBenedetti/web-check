.PHONY: help install run test lint format check ci \
        start stop restart logs logs-api status \
        clean clean-all cli

# ==============================================================================
# Variables
# ==============================================================================
PYTHON_VERSION ?= 3.12

# Colors
RED    = \033[0;31m
GREEN  = \033[0;32m
YELLOW = \033[1;33m
BLUE   = \033[0;34m
CYAN   = \033[0;36m
NC     = \033[0m

# ==============================================================================
##@ Help
# ==============================================================================

help: ## Display this help
	@echo ""
	@echo "$(BLUE)╔═══════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(BLUE)║              🔒 Web-Check Security Scanner                    ║$(NC)"
	@echo "$(BLUE)╚═══════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make $(CYAN)<target>$(NC)\n\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(CYAN)%-18s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(YELLOW)%s$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(YELLOW)Quick start:$(NC)"
	@echo "  1. cp .env.example .env"
	@echo "  2. make start"
	@echo "  3. make cli ARGS=\"scan quick https://example.com\""
	@echo ""

# ==============================================================================
##@ Docker
# ==============================================================================

start: ## Start all services (API + scanners)
	@echo "$(GREEN)🚀 Starting services...$(NC)"
	@docker compose up -d
	@echo "$(GREEN)✅ Ready — API: http://localhost:8000/docs$(NC)"

stop: ## Stop all containers
	@docker compose down
	@echo "$(GREEN)✅ Stopped$(NC)"

restart: stop start ## Restart all services

logs: ## Stream logs (all containers)
	@docker compose logs -f

logs-api: ## Stream API logs
	@docker compose logs -f api

status: ## Show container status
	@docker compose ps

# ==============================================================================
##@ Development
# ==============================================================================

install: ## Install all development dependencies
	@command -v uv >/dev/null 2>&1 || { echo "$(RED)❌ uv not found:  curl -LsSf https://astral.sh/uv/install.sh | sh$(NC)"; exit 1; }
	@uv python install $(PYTHON_VERSION)
	@uv sync --all-groups
	@echo "$(GREEN)✅ Development environment ready$(NC)"

run: ## Run API locally (without Docker)
	@uv run uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

ARGS ?= guide
cli: ## Run CLI wizard (or: make cli ARGS="scan quick https://example.com")
	@uv run python -m cli.main $(ARGS)

test: ## Run Python tests
	@uv run pytest -q

lint: ## Lint all code (ruff)
	@uv run ruff check .

format: ## Format all code (ruff)
	@uv run ruff format .

check: ## Run all quality checks (format + lint + typecheck)
	@echo "$(CYAN)▶ ruff format --check$(NC)"
	@uv run ruff format --check .
	@echo "$(CYAN)▶ ruff check$(NC)"
	@uv run ruff check .
	@echo "$(CYAN)▶ ty check$(NC)"
	@uv run ty check
	@echo "$(GREEN)✅ All checks passed$(NC)"

ci: ## Simulate CI pipeline locally (matches ci-cd.yml)
	@echo "$(BLUE)🧪 CI — Python$(NC)"
	@uv run ruff format --check .
	@uv run ruff check .
	@uv run ty check
	@uv run pytest -q
	@echo "$(GREEN)✅ Python OK$(NC)"
	@echo ""
	@echo "$(BLUE)🧪 CI — Docker build$(NC)"
	@docker build -t web-check-api:ci . -q
	@echo "$(GREEN)✅ Docker OK$(NC)"
	@echo ""
	@echo "$(GREEN)✅ All CI checks passed$(NC)"

# ==============================================================================
##@ Cleanup
# ==============================================================================

clean: ## Remove scan outputs
	@rm -rf outputs/* && mkdir -p outputs
	@echo "$(GREEN)✅ Outputs cleaned$(NC)"

clean-all: ## Remove containers, volumes, and outputs
	@echo "$(RED)⚠️  This will remove all containers, volumes and outputs.$(NC)"
	@read -p "Continue? [y/N] " -n 1 -r; echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		docker compose down -v; \
		docker system prune -f; \
		rm -rf outputs/*; \
		echo "$(GREEN)✅ Clean$(NC)"; \
	fi

.DEFAULT_GOAL := help
