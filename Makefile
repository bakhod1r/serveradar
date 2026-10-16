BIN := bin/serveradar
VERSION ?= v0.1.1
LDFLAGS := -s -w -X github.com/bakhod1r/serveradar/internal/application/scan.ToolVersion=$(VERSION)

.PHONY: build linux dist install test report run

# release artifacts + checksums consumed by install.sh
dist:
	mkdir -p dist
	for p in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
		os=$${p%/*}; arch=$${p#*/}; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o dist/serveradar-$$os-$$arch ./cmd/serveradar || exit 1; \
	done
	cd dist && (sha256sum serveradar-* 2>/dev/null || shasum -a 256 serveradar-*) > SHA256SUMS
	cp install.sh dist/
	cp RELEASE_NOTES.md dist/ 2>/dev/null || true

install:
	sudo ./install.sh

build:
	go build -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/serveradar

# static binaries for servers
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o bin/serveradar-linux-amd64 ./cmd/serveradar
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o bin/serveradar-linux-arm64 ./cmd/serveradar

test:
	go test ./...

report: build
	mkdir -p reports
	$(BIN) report --format md --output reports/$$(hostname)-$$(date +%Y%m%d-%H%M).md

run: build
	$(BIN)
