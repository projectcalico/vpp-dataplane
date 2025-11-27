# Integration Test Makefile
# Provides convenient commands for running integration tests
#
# GINKGO TEST STRUCTURE:
# ----------------------
# Tests are organized in a 3-level hierarchy:
#   1. Describe() - Top-level test suite (e.g., "vpp-manager")
#   2. Context()  - Sub-suite or scenario within a suite (e.g., "Interface", "VPPConfig")
#   3. It()       - Individual test case (e.g., "TapInterface", "memifInterface")
#
# HOW TO DEFINE A SUITE:
# ----------------------
# A "suite" in Ginkgo is defined using Describe() blocks:
#   var _ = Describe("My Test Suite", func() {
#       Context("My Test Sub-suite", func() {
#           It("Individual Test Case", func() {
#               // test code
#           })
#       })
#   })
#
# TEST FILTERING:
# --------------
# Use FOCUS, SUITE, or SKIP parameters to filter tests:
#   - FOCUS='pattern'  : Run only tests matching the regex pattern
#   - SUITE='name'     : Same as FOCUS (more semantic when filtering by suite name)
#   - SKIP='pattern'   : Exclude tests matching the regex pattern
#
# Patterns match against the full test description (Describe + Context + It names concatenated).
# Examples:
#   make test-vppmanager FOCUS='Interface'    # Runs all tests in "Interface" context
#   make test-vppmanager SUITE='vpp-manager'  # Runs entire test suite
#   make test-vppmanager FOCUS='TapInterface' # Runs just the TAP interface test
#   make test-vppmanager SKIP='memif'         # Skips memif-related tests
#
# Use 'make list-tests' to see all available suites, contexts, and test cases.

# Default VPP configuration for tests
VPP_IMAGE ?= calicovpp/vpp:latest
VPP_BINARY ?= /usr/bin/vpp
VPP_CONTAINER_EXTRA_ARGS ?=

# Export environment variables for tests
export VPP_IMAGE
export VPP_BINARY
export VPP_CONTAINER_EXTRA_ARGS

# Test timeout
VPP_DATAPLANE_TEST_TIMEOUT ?= 5m

.PHONY: help
help: ## Display this help message
	@echo "VPP Dataplane Integration Test Framework"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Environment variables:"
	@echo "  VPP_IMAGE                  	Docker image containing VPP (default: $(VPP_IMAGE))"
	@echo "  VPP_BINARY                 	Path to VPP binary in container (default: $(VPP_BINARY))"
	@echo "  VPP_CONTAINER_EXTRA_ARGS   	Additional docker run arguments (optional)"
	@echo "  VPP_DATAPLANE_TEST_TIMEOUT	Test timeout duration (default: $(VPP_DATAPLANE_TEST_TIMEOUT))"
	@echo ""
	@echo "Test Filtering (Ginkgo parameters):"
	@echo "  FOCUS='pattern'            	Run only tests matching pattern (regex)"
	@echo "  SUITE='suite name'         	Same as FOCUS (more semantic name)"
	@echo "  SKIP='pattern'             	Skip tests matching pattern (regex)"
	@echo ""
	@echo "How Test Filtering Works:"
	@echo "  • FOCUS/SUITE: Matches against Describe/Context/It descriptions"
	@echo "  • Supports regex patterns for flexible matching"
	@echo "  • Can match suite names, context names, or test case names"
	@echo "  • SKIP: Excludes tests that match the pattern"
	@echo "  • Patterns are case-sensitive by default"
	@echo ""
	@echo ""
	@echo "Examples:"
	@echo "  make test-vppmanager FOCUS='Interface'"
	@echo "  make test-vppmanager FOCUS='VPPConfig'"
	@echo "  make test-vppmanager FOCUS='TapInterface'"
	@echo "  make test-vppmanager SKIP='AF_PACKET|memif'"
	@echo ""
	@echo "Use 'make list-tests' to see all available test suites and cases"

.PHONY: list-tests
list-tests: ## List all available test suites and test cases
	@echo "VPP Manager Integration Test Suites"
	@echo "===================================="
	@echo ""
	@echo "Test Structure:"
	@echo "  Describe (Top-level suite)"
	@echo "    └─ Context (Sub-suite/scenario)"
	@echo "        └─ It (Individual test case)"
	@echo ""
	@echo "Available Test Suites and Cases:"
	@echo "────────────────────────────────────────────────────────────────"
	@grep -E '\s+(Describe|Context|It)\(' suites/vppmanager/*_test.go | \
		grep -v 'testCtx' | \
		sed 's/.*Describe("/📦 Suite: /; s/.*Context("/  📂 Context: /; s/.*It("/    ✓ Test: /; s/", func.*//' | \
		sed 's/suites\/vppmanager\/[^:]*://'
	@echo "────────────────────────────────────────────────────────────────"
	@echo ""
	@echo "Test Count Summary:"
	@SUITES=$$(grep -c 'Describe(' suites/vppmanager/*_test.go 2>/dev/null || echo 0); \
	CONTEXTS=$$(grep -c 'Context(' suites/vppmanager/*_test.go 2>/dev/null || echo 0); \
	TESTS=$$(grep -c 'It(' suites/vppmanager/*_test.go 2>/dev/null || echo 0); \
	echo "  📦 $$SUITES Describe suites"; \
	echo "  📂 $$CONTEXTS Context scenarios"; \
	echo "  ✓ $$TESTS Test cases"
	@echo ""
	@echo "Filter Examples:"
	@echo "  make test-vppmanager FOCUS='Interface'        # Run all tests in 'Interface' context"
	@echo "  make test-vppmanager FOCUS='VPPConfig'        # Run VPPConfig test"
	@echo "  make test-vppmanager FOCUS='TapInterface'     # Run only TAP interface test"
	@echo "  make test-vppmanager SKIP='memif'             # Skip memif-related tests"

.PHONY: test-vppmanager
test-vppmanager: ## Run VPP manager integration tests (use FOCUS='test name' or SUITE='suite name' to filter)
	@echo "Running VPP manager integration tests..."
	@GINKGO_ARGS="-ginkgo.v -v"; \
	if [ -n "$(FOCUS)" ]; then \
		echo "Focusing on tests matching: $(FOCUS)"; \
		GINKGO_ARGS="$$GINKGO_ARGS -ginkgo.focus='$(FOCUS)'"; \
	elif [ -n "$(SUITE)" ]; then \
		echo "Running test suite: $(SUITE)"; \
		GINKGO_ARGS="$$GINKGO_ARGS -ginkgo.focus='$(SUITE)'"; \
	fi; \
	if [ -n "$(SKIP)" ]; then \
		echo "Skipping tests matching: $(SKIP)"; \
		GINKGO_ARGS="$$GINKGO_ARGS -ginkgo.skip='$(SKIP)'"; \
	fi; \
	cd suites/vppmanager && go test -timeout $(VPP_DATAPLANE_TEST_TIMEOUT) $$GINKGO_ARGS

.PHONY: clean
clean: ## Clean up test artifacts and containers
	@echo "Cleaning up test containers..."
	@docker ps -a --filter "name=integration-test-" --format "{{.ID}}" | xargs -r docker rm -f
	@echo "Cleaning up test socket directories..."
	@rm -rf /tmp/vpp-test-*
	@echo "Cleanup complete"

.PHONY: check-env
check-env: ## Verify environment variables are set correctly
	@echo "Checking environment..."
	@if [ -z "$(VPP_IMAGE)" ]; then \
		echo "Error: VPP_IMAGE not set"; \
		exit 1; \
	fi
	@if [ -z "$(VPP_BINARY)" ]; then \
		echo "Error: VPP_BINARY not set"; \
		exit 1; \
	fi
	@echo "✓ VPP_IMAGE: $(VPP_IMAGE)"
	@echo "✓ VPP_BINARY: $(VPP_BINARY)"
	@if [ -n "$(VPP_CONTAINER_EXTRA_ARGS)" ]; then \
		echo "✓ VPP_CONTAINER_EXTRA_ARGS: $(VPP_CONTAINER_EXTRA_ARGS)"; \
	fi
	@echo "✓ VPP_DATAPLANE_TEST_TIMEOUT: $(VPP_DATAPLANE_TEST_TIMEOUT)"

	@echo ""
	@echo "Checking Go..."
	@go version > /dev/null 2>&1 || (echo "Error: go not available" && exit 1)
	@GV=$$(go version | awk '{print $$3}' | sed 's/^go//'); \
	GVM=$$(echo $$GV | awk -F. '{print $$1"."$$2}'); \
	REQUIRED=1.24; \
	if [ $$(printf "%s\n%s" $$REQUIRED $$GVM | sort -V | head -n1) != $$REQUIRED ]; then \
		echo "Error: go version $$GV is less than required $$REQUIRED"; \
		exit 1; \
	else \
		echo "✓ go version $$GV"; \
	fi
	@echo ""
	@echo "Checking Docker..."
	@docker version > /dev/null 2>&1 || (echo "Error: Docker not available" && exit 1)
	@DV=$$(docker version --format '{{.Client.Version}}' 2>/dev/null || docker version | head -n1 | sed 's/^Docker version //'); \
	echo "✓ docker version $$DV"
	@echo ""
	@echo "Checking if VPP image exists..."
	@if docker image inspect $(VPP_IMAGE) > /dev/null 2>&1; then \
		echo "✓ VPP image exists locally: $(VPP_IMAGE)"; \
		docker images --format "  {{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}" $(VPP_IMAGE) || true; \
	else \
		echo "Warning: VPP image $(VPP_IMAGE) not found locally"; \
	fi
	@echo ""
	@echo "Environment check complete!"

.PHONY: pull-vpp
pull-vpp: ## Pull the VPP Docker image
	@echo "Pulling VPP image: $(VPP_IMAGE)"
	docker pull $(VPP_IMAGE)

.PHONY: list-containers
list-containers: ## List running integration test containers
	@echo "Integration test containers:"
	@docker ps -a --filter "name=integration-test-" --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}"

.PHONY: install-ginkgo
install-ginkgo: ## Install Ginkgo CLI tool
	@echo "Installing Ginkgo v2 CLI..."
	go install github.com/onsi/ginkgo/v2/ginkgo@latest
	@echo "Ginkgo v2 installed successfully!"

.PHONY: lint
lint: ## Run golangci-lint
	@echo "Running golangci-lint..."
	golangci-lint run --color=never

# Default target
.DEFAULT_GOAL := help
