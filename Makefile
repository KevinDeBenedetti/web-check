# web-check — run `make` to list the targets.

COMPOSE := docker compose
COMPOSE_DEV := $(COMPOSE) -f docker-compose.yml -f docker-compose.dev.yml
COMPOSE_NATIVE := $(COMPOSE) -f docker-compose.yml -f docker-compose.native.yml

# Port of the API run on the host by `make native`.
NATIVE_PORT ?= 8000

# URLs of the running stack, with the port Docker actually published (API_PORT in .env).
SHOW_URLS = port=$$($(COMPOSE) port api 8000 2>/dev/null | sed 's/.*://'); \
	if [ -n "$$port" ]; then \
		echo "✅ Ready — UI http://localhost:$$port/ui/ · API http://localhost:$$port/docs"; \
	else echo "❌ The API container is not running: make logs SVC=api"; fi

# The API container runs as the host user, so the bind-mounted ./outputs and ./data
# stay writable, plus the group that owns the Docker socket (root inside Docker
# Desktop's VM on macOS).
APP_UID ?= $(shell id -u)
APP_GID ?= $(shell id -g)
ifeq ($(shell uname -s),Darwin)
DOCKER_GID ?= 0
else
DOCKER_GID ?= $(shell stat -c %g /var/run/docker.sock 2>/dev/null || echo 999)
endif
export APP_UID APP_GID DOCKER_GID

.DEFAULT_GOAL := help
.PHONY: help start dev stop logs native install cli test test-integration format check bin \
        ui-install ui-dev ui-build ui-check clean clean-all

help: ## List the targets
	@awk 'BEGIN {FS = ":.*## "} \
		/^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-11s\033[0m %s\n", $$1, $$2} \
		/^##@/ {printf "\n\033[1;33m%s\033[0m\n", substr($$0, 5)}' $(MAKEFILE_LIST)

##@ Docker: API + scanners

start: ## Start in the background and print the URLs
	@mkdir -p outputs data
	@$(COMPOSE) up -d --build
	@$(SHOW_URLS)

dev: ## Same with live reload of the API, then follow its logs (Ctrl+C stops)
	@mkdir -p outputs data
	@$(COMPOSE_DEV) up -d --build
	@$(SHOW_URLS)
	@trap '$(COMPOSE_DEV) stop' INT; $(COMPOSE_DEV) logs -f api

stop: ## Stop and remove the containers
	@$(COMPOSE) down

logs: ## Follow the logs (one service: make logs SVC=api)
	@$(COMPOSE) logs -f $(SVC)

##@ Native: API + UI on this machine, scanners in Docker

# Builds the UI, starts the scanner containers when Docker answers, then runs the
# API in the foreground (Ctrl+C stops it; `make stop` stops the containers). Without
# Docker, the Python modules (headers, DNS, SSLyze, Wapiti, sqlmap…) still run.
native: ## Run the API and the web UI on this machine (NATIVE_PORT, default 8000)
	@mkdir -p outputs data
	@test -d apps/web/node_modules || npm --prefix apps/web ci
	@npm --prefix apps/web run --silent build -- --logLevel warn
	@if docker info >/dev/null 2>&1; then $(COMPOSE_NATIVE) up -d zap nuclei nikto; \
	else echo "⚠️  Docker is not running: ZAP, Nuclei, Nikto and FFUF scans will fail"; fi
	@echo "✅ UI http://localhost:$(NATIVE_PORT)/ui/ · API http://localhost:$(NATIVE_PORT)/docs"
	@ZAP_HOST=127.0.0.1 ZAP_PORT=$${ZAP_PORT:-8090} uv run uvicorn api.main:app \
		--app-dir apps --host 127.0.0.1 --port $(NATIVE_PORT)

##@ Python

install: ## Install the dependencies (requires uv)
	@uv sync --all-groups

cli: ## Run the my-check wizard (arguments: make cli ARGS="...")
	@uv run my-check $(ARGS)

test: ## Run the tests
	@uv run pytest -q

test-integration: ## Run the real scanners against a local server (Nuclei and Nikto need make start)
	@uv run pytest -m integration

format: ## Format the code
	@uv run ruff format .

# Single-file executables for the host OS and CPU (on macOS: arm64 on Apple silicon,
# x86_64 on Intel). uv fetches PyInstaller for the build only.
# The apps' own modules are found by following their imports; dnspython loads its
# record types by name and questionary needs its data, so those two are collected.
PYINSTALLER = uv run --with pyinstaller pyinstaller --onefile --noconfirm --clean \
	--log-level WARN --exclude-module pytest \
	--paths $(CURDIR)/apps --distpath dist --workpath build/pyinstaller --specpath build/pyinstaller

bin: ## Build standalone my-check and web-check executables into dist/
	@$(PYINSTALLER) --name my-check --collect-submodules dns --collect-all questionary \
		$(CURDIR)/packaging/my_check_entry.py
	@$(PYINSTALLER) --name web-check $(CURDIR)/packaging/web_check_entry.py
	@./dist/my-check --help >/dev/null && ./dist/web-check --help >/dev/null
	@echo "✅ dist/my-check and dist/web-check built for $$(uname -sm)"

check: ## Format check, lint, type check and tests
	@uv run ruff format --check .
	@uv run ruff check .
	@uv run ty check
	@uv run pytest -q
	@echo "✅ All checks passed"

##@ Web UI: apps/web, Node.js 26+

ui-install: ## Install the dependencies
	@npm --prefix apps/web ci

ui-dev: ## Dev server on http://localhost:5173/ui/ (needs the API running)
	@npm --prefix apps/web run dev

ui-build: ## Build into apps/web/dist, which the API serves under /ui
	@npm --prefix apps/web run build

ui-check: ## Type check, test and build
	@npm --prefix apps/web run typecheck
	@npm --prefix apps/web test
	@npm --prefix apps/web run build
	@echo "✅ Web UI checks passed"

##@ Cleanup

clean: ## Delete the scan outputs
	@rm -rf outputs/*

clean-all: clean ## Also delete the containers and volumes
	@$(COMPOSE) down -v --remove-orphans
