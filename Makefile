PROJECT := leakdetector
MODULE  := github.com/asymmetric-effort/leakdetector
CMD     := ./cmd/leakdetector
BUILD   := ./build
COVER   := coverage.out
COVER_THRESHOLD := 98

GOOSES  := linux darwin windows
GOARCHS := amd64 arm64

VERSION_FILE := VERSION
VERSION      := $(shell cat $(VERSION_FILE) 2>/dev/null || echo "0.0.0")
LDFLAGS      := -s -w -X '$(MODULE)/internal/cli.Version=$(VERSION)'

.PHONY: all clean lint test cover build release release/patch release/minor release/major

all: clean lint test cover build

clean:
	@rm -rf $(BUILD)
	@mkdir -p $(BUILD)
	@echo "clean: done"

lint:
	@echo "lint: running go vet..."
	@go vet -v ./...
	@echo "lint: running govulncheck..."
	@govulncheck ./...
	@echo "lint: running staticcheck..."
	@staticcheck ./...
	@echo "lint: done"

test:
	@echo "test: running unit tests..."
	@go test -v -count=1 -race ./internal/...
	@echo "test: running integration tests..."
	@go test -v -count=1 -race -tags=integration ./test/integration/...
	@echo "test: running e2e tests..."
	@go test -v -count=1 -tags=e2e ./test/e2e/...
	@echo "test: done"

cover:
	@echo "cover: calculating coverage..."
	@go test -coverprofile=$(COVER) -covermode=atomic ./internal/...
	@COVERAGE=$$(go tool cover -func=$(COVER) | grep total | awk '{print $$3}' | tr -d '%'); \
	echo "cover: total coverage: $${COVERAGE}%"; \
	BELOW=$$(awk "BEGIN {print ($$COVERAGE < $(COVER_THRESHOLD)) ? 1 : 0}"); \
	if [ "$$BELOW" = "1" ]; then \
		echo "cover: FAIL - coverage $${COVERAGE}% is below $(COVER_THRESHOLD)% threshold"; \
		exit 1; \
	fi; \
	echo "cover: PASS"

build:
	@echo "build: cross-compiling $(PROJECT) v$(VERSION)..."
	@for goos in $(GOOSES); do \
		for goarch in $(GOARCHS); do \
			ext=""; \
			if [ "$$goos" = "windows" ]; then ext=".exe"; fi; \
			outdir="$(BUILD)/$$goos/$$goarch"; \
			mkdir -p "$$outdir"; \
			echo "build: $$goos/$$goarch"; \
			GOOS=$$goos GOARCH=$$goarch go build -ldflags "$(LDFLAGS)" -o "$$outdir/$(PROJECT)$$ext" $(CMD); \
		done; \
	done
	@echo "build: done"

release: release/patch

release/patch:
	@echo "release: bumping patch version..."
	@$(MAKE) _bump PART=patch

release/minor:
	@echo "release: bumping minor version..."
	@$(MAKE) _bump PART=minor

release/major:
	@echo "release: bumping major version..."
	@$(MAKE) _bump PART=major

_bump:
	@CURRENT=$(VERSION); \
	MAJOR=$$(echo $$CURRENT | cut -d. -f1); \
	MINOR=$$(echo $$CURRENT | cut -d. -f2); \
	PATCH=$$(echo $$CURRENT | cut -d. -f3); \
	case $(PART) in \
		major) MAJOR=$$((MAJOR + 1)); MINOR=0; PATCH=0;; \
		minor) MINOR=$$((MINOR + 1)); PATCH=0;; \
		patch) PATCH=$$((PATCH + 1));; \
	esac; \
	NEW="$$MAJOR.$$MINOR.$$PATCH"; \
	echo "$$NEW" > $(VERSION_FILE); \
	git add $(VERSION_FILE); \
	git commit -m "chore: bump version to v$$NEW"; \
	git tag "v$$NEW"; \
	echo "release: tagged v$$NEW"
