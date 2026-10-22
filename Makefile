# Every command CI runs lives here, so local runs and CI behave the same.

BINARY   := oraclint
PKG      := github.com/brennocm/oraclint
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
FUZZTIME ?= 30s

.PHONY: all build test test-race cover lint vuln fuzz golden-update demo clean

all: lint test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/oraclint

test:
	go test ./...

test-race:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -n 1

lint:
	golangci-lint run ./...

vuln:
	govulncheck ./...

# Runs every Fuzz* target for FUZZTIME each (go test allows one -fuzz target per run).
fuzz:
	@for pkg in $$(go list ./...); do \
		for target in $$(go test -list '^Fuzz' $$pkg | grep '^Fuzz'); do \
			echo "fuzzing $$pkg $$target"; \
			go test -run '^$$' -fuzz "^$$target$$" -fuzztime $(FUZZTIME) $$pkg || exit 1; \
		done; \
	done

# Only these packages define the -update flag (golden files and the README
# rule table); passing it to the others would fail.
golden-update:
	go test ./internal/report/ ./internal/rules/ -run Golden -update

demo: build
	PATH="$(CURDIR)/bin:$$PATH" vhs demo.tape

clean:
	rm -rf bin dist coverage.out
