.PHONY: help install test lint format check \
        start dev stop restart logs status \
        clean clean-all cli \
        ui-install ui-dev ui-build ui-test ui-check

PYTHON_VERSION ?= 3.12

# The API container runs as a non-root user: run it with the host user's ids so
# bind-mounted ./outputs and ./data stay writable, and grant it the group that
# owns the docker socket (root inside Docker Desktop's VM on macOS).
APP_UID ?= $(shell id -u)
APP_GID ?= $(shell id -g)
ifeq ($(shell uname -s),Darwin)
DOCKER_GID ?= 0
else
DOCKER_GID ?= $(shell stat -c %g /var/run/docker.sock 2>/dev/null || echo 999)
endif
export APP_UID APP_GID DOCKER_GID

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
	@mkdir -p outputs data
	@docker compose up -d --build
	@echo "✅ Ready — UI http://localhost:$${API_PORT:-8000}/ui/ · API http://localhost:$${API_PORT:-8000}/docs"

dev: ## Start all services with live code reload of the API (foreground)
	@mkdir -p outputs data
	@docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

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
##@ Web UI (apps/web)
# ==============================================================================

ui-install: ## Install web UI dependencies (requires Node.js 24+)
	@npm --prefix apps/web ci

ui-dev: ## Run the web UI with hot reload on http://localhost:5173/ui/ (API must be running)
	@npm --prefix apps/web run dev

ui-build: ## Build the web UI into apps/web/dist (served by the API under /ui)
	@npm --prefix apps/web run build

ui-test: ## Run web UI unit tests
	@npm --prefix apps/web test

ui-check: ## Typecheck, test and build the web UI
	@npm --prefix apps/web run typecheck
	@npm --prefix apps/web test
	@npm --prefix apps/web run build
	@echo "✅ Web UI checks passed"

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
