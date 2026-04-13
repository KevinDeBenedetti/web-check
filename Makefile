.PHONY: help install test lint format check \
        start stop restart logs status \
        clean clean-all cli

PYTHON_VERSION ?= 3.12

# ==============================================================================
##@ Help
# ==============================================================================

help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n\n"} \
		/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1;33m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

# ==============================================================================
##@ Docker
# ==============================================================================

start: ## Start all services (API + scanners)
	@docker compose up -d
	@echo "✅ Ready — http://localhost:$${API_PORT:-8001}/docs"

stop: ## Stop all containers
	@docker compose down

restart: stop start ## Restart all services

logs: ## Stream logs (all or: make logs SVC=api)
	@docker compose logs -f $(SVC)

status: ## Show container status
	@docker compose ps

# ==============================================================================
##@ Development
# ==============================================================================

install: ## Install dev dependencies (requires uv)
	@command -v uv >/dev/null 2>&1 || { echo "❌ uv not found: curl -LsSf https://astral.sh/uv/install.sh | sh"; exit 1; }
	@uv python install $(PYTHON_VERSION)
	@uv sync --all-groups
	@echo "✅ Ready"

cli: ## Launch the interactive security scanner wizard
	@uv run my-check $(ARGS)

test: ## Run tests
	@uv run pytest -q

lint: ## Lint code (ruff)
	@uv run ruff check .

format: ## Format code (ruff)
	@uv run ruff format .

check: ## Run all quality checks (format + lint + type + test)
	@uv run ruff format --check .
	@uv run ruff check .
	@uv run ty check
	@uv run pytest -q
	@echo "✅ All checks passed"

# ==============================================================================
##@ Cleanup
# ==============================================================================

clean: ## Remove scan outputs
	@rm -rf outputs/* && mkdir -p outputs
	@echo "✅ Outputs cleaned"

clean-all: clean ## Remove containers, volumes, and outputs
	@docker compose down -v --remove-orphans
	@echo "✅ All cleaned"

.DEFAULT_GOAL := help
