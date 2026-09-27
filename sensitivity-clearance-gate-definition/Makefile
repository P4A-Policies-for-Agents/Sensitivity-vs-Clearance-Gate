.PHONY: build
build: ## Build the policy definition
	@anypoint-cli-v4 pdk policy-definition build

.PHONY: publish
publish: build ## Publish definition to exchange as -DEV asset
	@anypoint-cli-v4 pdk policy-definition publish --dev

.PHONY: release
release: build ## Publish definition to exchange
	@anypoint-cli-v4 pdk policy-definition publish

.PHONY: release-local
release-local: build ## Publish definition to local fs
	@anypoint-cli-v4 pdk policy-definition publish-local

ifneq ($(OS), Windows_NT)
all: help

.PHONY: help
help: ## Shows this help
	@echo 'Usage: make <target>'
	@echo ''
	@echo 'Available targets are:'
	@echo ''
	@grep -Eh '^\w[^:]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-6s\033[0m %s\n", $$1, $$2}' \
		| sort
endif
