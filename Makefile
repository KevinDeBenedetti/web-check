.PHONY: help scan quick custom clean start stop status report open install

# ══════════════════════════════════════════════════════════════════════════════
# Variables
# ══════════════════════════════════════════════════════════════════════════════
TARGET ?= https://kevindb.dev
MODE ?= full
TOOLS ?= zap,nuclei,nikto,testssl,ffuf
OUTPUT_BASE = outputs

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
	@echo "$(BLUE)║              🔒 Security Scanner Suite                         ║$(NC)"
	@echo "$(BLUE)╚════════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make $(CYAN)<target>$(NC) TARGET=<url>\n\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(CYAN)%-15s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(BOLD)%s$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(YELLOW)Examples:$(NC)"
	@echo "  make scan TARGET=https://my-site.vercel.app"
	@echo "  make quick TARGET=https://my-site.com"
	@echo "  make zap TARGET=https://site.com"
	@echo ""
	@echo "$(YELLOW)Output structure:$(NC)"
	@echo "  outputs/"
	@echo "  └── YYYYMMDD-HHMMSS/"
	@echo "      ├── scans/       (raw results)"
	@echo "      ├── logs/        (execution logs)"
	@echo "      ├── report.html  (consolidated report)"
	@echo "      └── metadata.json"
	@echo ""

# ══════════════════════════════════════════════════════════════════════════════
##@ Combined Scans
# ══════════════════════════════════════════════════════════════════════════════

scan: start ## Complete scan (all tools, 30-60 min)
	$(call setup_output)
	@echo "$(GREEN)🔍 Complete scan in progress...$(NC)"
	@./scripts/scan.sh "$(TARGET)" "$(OUTPUT_DIR)" "full"

quick: start ## Quick scan (Nuclei + Nikto, 5-10 min)
	$(call setup_output)
	@echo "$(GREEN)⚡ Quick scan in progress...$(NC)"
	@./scripts/scan.sh "$(TARGET)" "$(OUTPUT_DIR)" "quick"

custom: start ## Custom scan (specify TOOLS=zap,nuclei,...)
	$(call setup_output)
	@echo "$(GREEN)🎯 Custom scan: $(TOOLS)$(NC)"
	@./scripts/scan.sh "$(TARGET)" "$(OUTPUT_DIR)" "custom" "$(TOOLS)"

# ══════════════════════════════════════════════════════════════════════════════
##@ Individual Scans
# ══════════════════════════════════════════════════════════════════════════════

zap: ## Scan only with ZAP (full DAST)
	$(call setup_output)
	@echo "$(GREEN)🔍 ZAP scan...$(NC)"
	@docker run --rm -v $(PWD)/$(SCANS_DIR):/zap/wrk:rw zaproxy/zap-stable:latest \
		zap-baseline.py -t $(TARGET) -r zap.html -J zap.json -I \
		> $(LOGS_DIR)/zap.log 2>&1 || true
	@$(MAKE) _finalize-scan TOOL=zap OUTPUT_DIR=$(OUTPUT_DIR)

nuclei: start ## Scan only with Nuclei (CVE)
	$(call setup_output)
	@echo "$(GREEN)🔍 Nuclei scan...$(NC)"
	@docker exec security-scanner-nuclei nuclei -u $(TARGET) \
		-severity critical,high,medium -jsonl -o /output/nuclei.json \
		> $(LOGS_DIR)/nuclei.log 2>&1 || true
	@mv $(OUTPUT_BASE)/nuclei.json $(SCANS_DIR)/ 2>/dev/null || true
	@$(MAKE) _finalize-scan TOOL=nuclei OUTPUT_DIR=$(OUTPUT_DIR)

nikto: start ## Scan only with Nikto (web server)
	$(call setup_output)
	@echo "$(GREEN)🔍 Nikto scan...$(NC)"
	@docker exec security-scanner-nikto perl /nikto/nikto.pl -h $(TARGET) \
		-output /output/nikto.html -Format html \
		> $(LOGS_DIR)/nikto.log 2>&1 || true
	@mv $(OUTPUT_BASE)/nikto.html $(SCANS_DIR)/ 2>/dev/null || true
	@mv $(OUTPUT_BASE)/nikto*.html $(SCANS_DIR)/ 2>/dev/null || true
	@$(MAKE) _finalize-scan TOOL=nikto OUTPUT_DIR=$(OUTPUT_DIR)

testssl: start ## Scan only SSL/TLS
	$(call setup_output)
	@echo "$(GREEN)🔍 testssl.sh scan...$(NC)"
	@$(eval DOMAIN=$(shell echo $(TARGET) | sed -e 's|^[^/]*//||' -e 's|/.*$$||'))
	@docker exec security-scanner-testssl /home/testssl/testssl.sh \
		--jsonfile /output/testssl.json $(DOMAIN) \
		> $(LOGS_DIR)/testssl.log 2>&1 || true
	@mv $(OUTPUT_BASE)/testssl.json $(SCANS_DIR)/ 2>/dev/null || true
	@$(MAKE) _finalize-scan TOOL=testssl OUTPUT_DIR=$(OUTPUT_DIR)

ffuf: start ## Scan only with Ffuf (fuzzing)
	$(call setup_output)
	@echo "$(GREEN)🔍 Ffuf scan...$(NC)"
	@if [ ! -f config/wordlists/common.txt ]; then \
		mkdir -p config/wordlists; \
		curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
			-o config/wordlists/common.txt; \
	fi
	@docker cp config/wordlists/common.txt security-scanner-ffuf:/tmp/wordlist.txt 2>/dev/null || true
	@docker exec security-scanner-ffuf ffuf -u $(TARGET)/FUZZ \
		-w /tmp/wordlist.txt -mc 200,201,301,302,401,403 \
		-o /output/ffuf.json -of json -t 10 -s \
		> $(LOGS_DIR)/ffuf.log 2>&1 || true
	@mv $(OUTPUT_BASE)/ffuf.json $(SCANS_DIR)/ 2>/dev/null || true
	@$(MAKE) _finalize-scan TOOL=ffuf OUTPUT_DIR=$(OUTPUT_DIR)

# ══════════════════════════════════════════════════════════════════════════════
##@ Docker Management
# ══════════════════════════════════════════════════════════════════════════════

install: ## Install/Update Docker images
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

# ══════════════════════════════════════════════════════════════════════════════
##@ Reports and Results
# ══════════════════════════════════════════════════════════════════════════════

report: ## Generate HTML report for the latest scan
	@$(eval LATEST=$(shell ls -td $(OUTPUT_BASE)/*/ 2>/dev/null | head -1))
	@if [ -n "$(LATEST)" ]; then \
		echo "$(BLUE)📊 Generating report...$(NC)"; \
		./scripts/report.sh "$(LATEST)"; \
		echo "$(GREEN)✅ Report generated: $(LATEST)report.html$(NC)"; \
	else \
		echo "$(RED)❌ No scan found$(NC)"; \
	fi

open: ## Open the latest report in browser
	@$(eval LATEST=$(shell ls -td $(OUTPUT_BASE)/*/ 2>/dev/null | head -1))
	@if [ -f "$(LATEST)report.html" ]; then \
		open "$(LATEST)report.html" 2>/dev/null || xdg-open "$(LATEST)report.html" 2>/dev/null || true; \
		echo "$(GREEN)📂 Opening $(LATEST)report.html$(NC)"; \
	else \
		echo "$(RED)❌ No report found$(NC)"; \
	fi

list: ## List all scans performed
	@echo ""
	@echo "$(BLUE)📋 Available scans:$(NC)"
	@echo ""
	@for dir in $(OUTPUT_BASE)/*/; do \
		if [ -d "$$dir" ]; then \
			scan_id=$$(basename "$$dir"); \
			files=$$(ls "$$dir/scans" 2>/dev/null | wc -l | tr -d ' '); \
			has_report=$$([ -f "$$dir/report.html" ] && echo "✅" || echo "❌"); \
			echo "  📁 $$scan_id  |  $$files files  |  Report: $$has_report"; \
		fi \
	done || echo "  No scan found"
	@echo ""

tree: ## Show file structure of the latest scan
	@$(eval LATEST=$(shell ls -td $(OUTPUT_BASE)/*/ 2>/dev/null | head -1))
	@if [ -n "$(LATEST)" ]; then \
		echo "$(BLUE)🌳 Structure of $(LATEST)$(NC)"; \
		find "$(LATEST)" -type f | sed 's|$(LATEST)||' | sort; \
	else \
		echo "$(RED)❌ No scan found$(NC)"; \
	fi

clean: ## Delete all results
	@echo "$(RED)⚠️  Deleting ALL results...$(NC)"
	@rm -rf $(OUTPUT_BASE)/*
	@echo "$(GREEN)✅ All results deleted$(NC)"

# ══════════════════════════════════════════════════════════════════════════════
##@ Utilities
# ══════════════════════════════════════════════════════════════════════════════

logs: ## Show Docker logs
	@docker-compose logs -f

shell-zap: ## Interactive shell in ZAP container
	@docker exec -it security-scanner-zap /bin/bash

shell-nuclei: ## Interactive shell in Nuclei container
	@docker exec -it security-scanner-nuclei /bin/sh

update-templates: start ## Update Nuclei templates
	@echo "$(BLUE)🔄 Updating Nuclei templates...$(NC)"
	@docker exec security-scanner-nuclei nuclei -update-templates
	@echo "$(GREEN)✅ Templates updated$(NC)"

check: ## Check prerequisites (Docker, etc.)
	@echo "$(BLUE)🔍 Checking prerequisites...$(NC)"
	@command -v docker >/dev/null 2>&1 || { echo "$(RED)❌ Docker not installed$(NC)"; exit 1; }
	@docker info >/dev/null 2>&1 || { echo "$(RED)❌ Docker daemon not started$(NC)"; exit 1; }
	@command -v docker-compose >/dev/null 2>&1 || docker compose version >/dev/null 2>&1 || { echo "$(RED)❌ docker-compose not installed$(NC)"; exit 1; }
	@echo "$(GREEN)✅ All prerequisites satisfied$(NC)"

version: ## Show version
	@echo "Security Scanner"

# ══════════════════════════════════════════════════════════════════════════════
##@ CI/CD
# ══════════════════════════════════════════════════════════════════════════════

ci-scan: install ## Scan for CI/CD (non-interactive)
	$(call setup_output)
	@$(MAKE) scan TARGET=$(TARGET) || true
	@if [ -f "$(OUTPUT_DIR)/report.json" ]; then \
		critical=$$(cat "$(OUTPUT_DIR)/report.json" | jq -r '.summary.critical // 0'); \
		if [ "$$critical" -gt 0 ]; then \
			echo "$(RED)❌ $$critical critical vulnerabilities detected$(NC)"; \
			exit 1; \
		fi \
	fi

# ══════════════════════════════════════════════════════════════════════════════
# Internal targets (private)
# ══════════════════════════════════════════════════════════════════════════════

# Create output directory and export variables
define setup_output
	$(eval SCAN_ID := $(shell date +%Y%m%d-%H%M%S))
	$(eval OUTPUT_DIR := $(OUTPUT_BASE)/$(SCAN_ID))
	$(eval SCANS_DIR := $(OUTPUT_DIR)/scans)
	$(eval LOGS_DIR := $(OUTPUT_DIR)/logs)
	@mkdir -p $(SCANS_DIR) $(LOGS_DIR)
	@echo '{"scan_id":"$(SCAN_ID)","target":"$(TARGET)","started_at":"'$$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}' > $(OUTPUT_DIR)/metadata.json
endef

_finalize-scan:
	@./scripts/report.sh "$(OUTPUT_DIR)" 2>/dev/null || true
	@echo "$(GREEN)✅ Scan $(TOOL) completed$(NC)"
	@echo ""
	@echo "$(BLUE)📁 Results: $(OUTPUT_DIR)$(NC)"
	@echo "   └── scans/$(TOOL).*"
	@echo "   └── logs/$(TOOL).log"
	@echo "   └── report.html"
	@echo ""
	@if [ -f "$(OUTPUT_DIR)/report.html" ]; then \
		open "$(OUTPUT_DIR)/report.html" 2>/dev/null || xdg-open "$(OUTPUT_DIR)/report.html" 2>/dev/null || true; \
	fi

# ══════════════════════════════════════════════════════════════════════════════
# Lint
# ══════════════════════════════════════════════════════════════════════════════

lint:
	@command -v shellcheck >/dev/null || (echo "❌ Install shellcheck: brew install shellcheck" && exit 1)
	@shellcheck scripts/*.sh scripts/lib/*.sh 2>&1 | grep -v "SC2034" || echo "✅ Code OK"

.DEFAULT_GOAL := help
