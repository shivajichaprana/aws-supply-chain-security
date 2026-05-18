# =============================================================================
# Makefile -- aws-supply-chain-security
# =============================================================================
#
# Convenience wrappers around the most common operations. Every target is
# safe to run from a clean checkout; no implicit state is assumed.
#
# Targets:
#   init / plan / apply / destroy -- Terraform lifecycle
#   fmt / lint / test / scan      -- pre-PR checks
#   test-policies                 -- run OPA tests on Gatekeeper policies
#   drift-check                   -- inline vs standalone Rego drift
#   dryrun                        -- locally simulate the buildspec phases
#   help                          -- list targets with descriptions
#
# All Terraform targets accept a TF_DIR override (default: terraform/) so the
# Makefile remains useful even if the directory layout changes.
# =============================================================================

SHELL          := /usr/bin/env bash
.SHELLFLAGS    := -eu -o pipefail -c
.DEFAULT_GOAL  := help

TF_DIR         ?= terraform
POLICY_DIR     ?= policies/gatekeeper
TESTS_DIR      ?= tests/gatekeeper
TF             ?= terraform
OPA            ?= opa
TRIVY          ?= trivy
TFLINT         ?= tflint
YAMLLINT       ?= yamllint

# Color helpers (gracefully degrade if `tput` is unavailable).
ANSI_GREEN := $(shell tput setaf 2 2>/dev/null || true)
ANSI_RESET := $(shell tput sgr0    2>/dev/null || true)

define _banner
	@echo ""
	@echo "$(ANSI_GREEN)>>> $(1)$(ANSI_RESET)"
endef

.PHONY: help
help: ## list all targets with descriptions
	@echo ""
	@echo "Available targets:"
	@awk -F'[: ##]' '/^[a-zA-Z0-9_-]+:.*##/ {printf "  %-20s %s\n", $$1, $$NF}' $(MAKEFILE_LIST)
	@echo ""

# ---------------------------------------------------------------------------
# Terraform lifecycle
# ---------------------------------------------------------------------------

.PHONY: init
init: ## terraform init (backend disabled for local validation)
	$(call _banner,terraform init)
	@cd $(TF_DIR) && $(TF) init -backend=false -input=false

.PHONY: plan
plan: ## terraform plan
	$(call _banner,terraform plan)
	@cd $(TF_DIR) && $(TF) plan -out=tfplan.bin

.PHONY: apply
apply: ## terraform apply (uses tfplan.bin if present)
	$(call _banner,terraform apply)
	@cd $(TF_DIR) && \
		if [ -f tfplan.bin ]; then $(TF) apply -auto-approve tfplan.bin; \
		else $(TF) apply -auto-approve; fi

.PHONY: destroy
destroy: ## terraform destroy
	$(call _banner,terraform destroy)
	@cd $(TF_DIR) && $(TF) destroy -auto-approve

# ---------------------------------------------------------------------------
# Pre-PR checks
# ---------------------------------------------------------------------------

.PHONY: fmt
fmt: ## terraform fmt + opa fmt (auto-fix)
	$(call _banner,formatting)
	@$(TF) fmt -recursive $(TF_DIR)
	@$(OPA) fmt -w $(POLICY_DIR) $(TESTS_DIR)

.PHONY: fmt-check
fmt-check: ## verify formatting without modifying files
	$(call _banner,fmt-check)
	@$(TF) fmt -check -recursive -diff $(TF_DIR)
	@$(OPA) fmt --diff $(POLICY_DIR) $(TESTS_DIR)

.PHONY: lint
lint: ## tflint, yamllint, shellcheck
	$(call _banner,lint)
	@cd $(TF_DIR) && $(TFLINT) --init && $(TFLINT) --recursive --minimum-failure-severity=warning
	@$(YAMLLINT) -c .yamllint.yaml policies pipelines .github/workflows
	@shopt -s nullglob && shellcheck -S warning scripts/*.sh tests/*.sh

.PHONY: test
test: test-policies drift-check ## run all unit-test suites

.PHONY: test-policies
test-policies: ## opa test on Gatekeeper policies
	$(call _banner,opa test)
	@$(OPA) check $(POLICY_DIR) $(TESTS_DIR)
	@$(OPA) test -v --explain=fails $(POLICY_DIR) $(TESTS_DIR)

.PHONY: drift-check
drift-check: ## verify inline Rego in constraints.yaml matches standalone .rego
	$(call _banner,drift check)
	@bash tests/check-constraints-drift.sh

.PHONY: scan
scan: ## trivy config scan over the repo
	$(call _banner,trivy config scan)
	@$(TRIVY) config --severity HIGH,CRITICAL --exit-code 1 .

.PHONY: dryrun
dryrun: ## locally simulate the CodeBuild buildspec phases
	$(call _banner,codebuild dry-run)
	@bash tests/codebuild-dryrun.sh

# ---------------------------------------------------------------------------
# CI fan-in -- mirror what the GitHub Actions workflow runs.
# ---------------------------------------------------------------------------

.PHONY: ci
ci: fmt-check lint test scan ## run every pre-PR check (same as CI)
	$(call _banner,ci: all checks passed)

# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------

.PHONY: clean
clean: ## remove transient files
	$(call _banner,clean)
	@find $(TF_DIR) -name '.terraform' -type d -exec rm -rf {} + 2>/dev/null || true
	@find $(TF_DIR) -name 'tfplan.bin' -delete 2>/dev/null || true
	@find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "done."

.PHONY: print-tools
print-tools: ## show tool versions used by this Makefile
	@echo "terraform: $$($(TF) version | head -1)"
	@echo "opa:       $$($(OPA) version | head -1)"
	@echo "trivy:     $$($(TRIVY) --version | head -1)"
	@echo "tflint:    $$($(TFLINT) --version | head -1)"
	@echo "yamllint:  $$($(YAMLLINT) --version)"
