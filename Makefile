.DEFAULT_GOAL := help
UV := uv

# One shared version (packages/gapscan-core/src/gapscan/core/version.py) tags the published image.
VERSION := $(shell sed -n 's/^__version__ = "\(.*\)"/\1/p' packages/gapscan-core/src/gapscan/core/version.py)
# Container registry the offline image is published to. Override to point elsewhere.
REGISTRY ?= ghcr.io
REGISTRY_OWNER ?= shawaf
IMAGE := $(REGISTRY)/$(REGISTRY_OWNER)/gapscan

.PHONY: help setup lint test eval eval-quick bundle docker-build docker-test docker-push docker-save doctor dashboard manager rules-test sbom freeze dmg clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

setup: ## Install dependencies with uv
	$(UV) sync --all-groups

lint: ## Run ruff, mypy and the import-boundary contracts
	$(UV) run ruff check packages tests
	$(UV) run ruff format --check packages tests
	$(UV) run mypy
	$(UV) run lint-imports --no-logo

rules-test: ## Test GapScan's own Semgrep rules against their vulnerable/safe cases
	for l in kotlin swift dart python javascript java go csharp php; do semgrep --test --config packages/gapscan-security/src/gapscan/rules/semgrep/$$l tests/rules/$$l --metrics=off --disable-version-check || exit 1; done

test: ## Run the test suite
	$(UV) run pytest

eval: ## Evaluate on the labeled fixtures and OWASP Benchmark (needs the local model; `gapscan eval fetch` first)
	$(UV) run gapscan eval run

eval-quick: ## Scanner-only evaluation (no model): fixtures + benchmark scorecard
	$(UV) run gapscan eval run --no-triage

BUNDLE ?= build/bundle/gapscan-bundle.tar.gz

bundle: ## Build an offline bundle
	$(UV) run gapscan bundle

docker-build: ## Build the offline image from $(BUNDLE) (needs Docker and network once)
	mkdir -p docker/bundle && cp $(BUNDLE) docker/bundle/gapscan-bundle.tar.gz
	$(UV) export --frozen --no-dev --no-hashes --no-emit-project --no-emit-workspace -o docker/requirements.lock
	docker build $(DOCKER_BUILD_ARGS) -f docker/Dockerfile -t gapscan-offline .

docker-test: ## Scan the fixture inside `docker run --network none` and check the result
	sh docker/test-offline.sh

docker-push: ## Push the built gapscan-offline image to the private registry ($(IMAGE))
	docker tag gapscan-offline $(IMAGE):$(VERSION)
	docker tag gapscan-offline $(IMAGE):latest
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):latest

docker-save: ## Save the built image to a tarball for air-gapped handoff -> dist/
	mkdir -p dist
	docker save gapscan-offline -o dist/gapscan-offline-$(VERSION).tar
	@ls -la dist/gapscan-offline-$(VERSION).tar

doctor: ## Check scanners, model and DBs
	$(UV) run gapscan doctor

sbom: ## CycloneDX SBOM of GapScan itself -> build/gapscan.cdx.json (offline, needs data/trivy-cache)
	mkdir -p build
	trivy fs --cache-dir data/trivy-cache --skip-db-update --skip-java-db-update --offline-scan --quiet \
		--format cyclonedx --scanners license --skip-dirs data --skip-dirs build --skip-dirs .venv \
		--output build/gapscan.cdx.json .

dashboard: ## Build the dashboard frontend into the single-file template (needs node)
	cd dashboard && npm ci && npm run typecheck && npm test && npm run build
	cp dashboard/dist/index.html packages/gapscan-security/src/gapscan/report/templates/dashboard.html
	@ls -la packages/gapscan-security/src/gapscan/report/templates/dashboard.html

manager: ## Build the management UI (gapscan serve) into its single-file template
	cd dashboard && npm ci && npm run typecheck && npx vite build -c vite.manager.config.ts
	mkdir -p packages/gapscan-local/src/gapscan/server/templates
	cp dashboard/dist-manager/manager.html packages/gapscan-local/src/gapscan/server/templates/manager.html
	@ls -la packages/gapscan-local/src/gapscan/server/templates/manager.html

freeze: ## Build the packaged app into dist/gapscan/ (needs the built dashboards: make dashboard manager)
	$(UV) run python tools/fetch_bundled_tools.py
	cd packaging && $(UV) run --group build --group desktop pyinstaller gapscan.spec --noconfirm --distpath ../dist --workpath ../build/pyinstaller
	@ls -la dist/gapscan/gapscan && du -sh dist/gapscan

dmg: freeze ## Package dist/GapScan.app into dist/GapScan.dmg (macOS, unsigned)
	rm -f dist/GapScan.dmg
	hdiutil create -volname GapScan -srcfolder dist/GapScan.app -ov -format UDZO dist/GapScan.dmg
	@ls -la dist/GapScan.dmg

clean: ## Remove caches and build artifacts
	rm -rf .mypy_cache .pytest_cache .ruff_cache dist build
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
