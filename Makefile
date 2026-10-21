.DEFAULT_GOAL := help
SHELL := /bin/bash
PATH := $(CURDIR)/bin:$(CURDIR)/.venv/bin:$(PATH)
export PATH
PYTHON := $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: help setup cluster-up cluster-down deploy-samples lint fmt test test-integration test-all schema docs validate scan screenshots metrics-record dashboards-up dashboards-down clean
help: ## list available targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## install Python package and development dependencies
	python3 -m venv .venv
	.venv/bin/python -m pip install -U pip
	.venv/bin/python -m pip install -e '.[dev]'
	./scripts/install-tools.sh
	.venv/bin/pre-commit install

cluster-up: ## create the local kind cluster
	kind get clusters | grep -qx infraguard || kind create cluster --name infraguard --config cluster/kind-config.yaml --image kindest/node:v1.30.2

cluster-down: ## delete the local kind cluster
	kind delete cluster --name infraguard

deploy-samples: ## deploy compliant and deliberately noncompliant charts
	kubectl create namespace ig-compliant --dry-run=client -o yaml | kubectl apply -f -
	kubectl create namespace ig-noncompliant --dry-run=client -o yaml | kubectl apply -f -
	helm upgrade --install compliant samples/charts/compliant-app -n ig-compliant
	helm upgrade --install noncompliant samples/charts/noncompliant-app -n ig-noncompliant
	kubectl rollout status deployment/compliant-app -n ig-compliant --timeout=120s

lint: ## run formatting, static analysis, and repository safety checks
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m mypy --strict src
	./scripts/check_no_plans.sh

fmt: ## format Python and Terraform sources
	$(PYTHON) -m ruff format .
	@if command -v terraform >/dev/null; then terraform fmt -recursive samples/terraform; fi

test: ## run offline tests
	@if command -v opa >/dev/null; then opa test policies/kubernetes/*.rego policies/terraform/*.rego -v; else echo "opa unavailable: Rego tests skipped"; fi
	$(PYTHON) -m pytest -m 'not integration' --cov=infraguard --cov-report=term-missing

test-integration: ## run tests requiring kind
	$(PYTHON) -m pytest -m integration --timeout=300

test-all: test test-integration ## run all tests

schema: ## regenerate the JSON report schema
	$(PYTHON) scripts/generate_schema.py

docs: ## regenerate policy documentation
	$(PYTHON) -m infraguard policies list --format md > docs/POLICIES.md

validate: ## validate all compliant examples
	$(PYTHON) -m infraguard validate samples/manifests/compliant --fail-on LOW
	$(PYTHON) -m infraguard validate --helm-chart samples/charts/compliant-app --fail-on LOW

scan: ## run the full noncompliant demonstration scan
	$(PYTHON) -m infraguard validate samples/manifests/noncompliant --plan-json samples/terraform/plan-fixtures/noncompliant.plan.fixture.json --fail-on NONE --format table --format json --format markdown --metrics-file reports/metrics.prom

screenshots: ## regenerate README visuals from real InfraGuard output
	$(PYTHON) scripts/generate_screenshots.py

metrics-record: ## print reproducible repository metrics
	$(PYTHON) scripts/record_metrics.py

dashboards-up: ## start optional Prometheus and Grafana services
	docker compose -f dashboards/docker-compose.yml up -d

dashboards-down: ## stop optional observability services
	docker compose -f dashboards/docker-compose.yml down

clean: ## remove generated local output
	rm -rf reports audit .cache .coverage htmlcov

