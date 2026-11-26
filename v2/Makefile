GO ?= go
CONTRACT_PYTHON ?= python3
REVISION := $(shell git rev-parse HEAD)
VERSION ?= 0.0.0-c13
DIRTY := $(shell test -z "$$(git status --porcelain --untracked-files=normal)" && echo false || echo true)
MODULE := github.com/QgMixtate/surveyscan/v2
BUILD_FLAGS = -X $(MODULE)/internal/platform/buildinfo.Version=$(VERSION) -X $(MODULE)/internal/platform/buildinfo.Revision=$(REVISION) -X $(MODULE)/internal/platform/buildinfo.Dirty=$(DIRTY)

.PHONY: build rust packages test vet contracts integration dev-up dev-down fmt-check verify
build:
	mkdir -p .dist/contracts
	$(GO) version
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -p 2 -ldflags '$(BUILD_FLAGS)' -o .dist/surveyscan-server ./cmd/surveyscan-server
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -p 2 -ldflags '$(BUILD_FLAGS)' -o .dist/surveyscan-collector ./cmd/surveyscan-collector
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -p 2 -ldflags '$(BUILD_FLAGS)' -o .dist/surveyscan-agent ./cmd/surveyscan-agent
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -p 2 -ldflags '$(BUILD_FLAGS)' -o .dist/surveyscanctl ./cmd/surveyscanctl
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -p 2 -ldflags '$(BUILD_FLAGS)' -o .dist/surveyscan-portable ./cmd/surveyscan-portable
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -mod=readonly -trimpath -p 2 -ldflags '$(BUILD_FLAGS)' -o .dist/surveyscan-portable.exe ./cmd/surveyscan-portable # Windows-аудит ПК (C23)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -mod=readonly -trimpath -p 2 -ldflags '$(BUILD_FLAGS)' -o .dist/surveyscan-collector.exe ./cmd/surveyscan-collector # MSI collector (C52.04)
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -p 2 -ldflags '$(BUILD_FLAGS)' -o .dist/surveyscan-router ./cmd/surveyscan-router
	CGO_ENABLED=0 $(GO) build -mod=readonly -trimpath -p 2 -o .dist/testsshd ./scripts/testsshd # только для смоков C51.03
	cp contracts/*.json .dist/contracts/
	chmod 755 .dist .dist/contracts .dist/surveyscan-* .dist/surveyscanctl
	chmod 644 .dist/contracts/*.json
# Rust-агент и Rust-portable (C52): Linux (musl, статически) и Windows — в .dist/rust; нужны rustup-цели
# x86_64-unknown-linux-musl, x86_64-pc-windows-gnu, musl-tools и gcc-mingw-w64-x86-64.
rust:
	cd agent-rs && cargo build --release --locked --target x86_64-unknown-linux-musl && cargo build --release --locked --target x86_64-pc-windows-gnu
	mkdir -p .dist/rust/linux .dist/rust/windows
	cp agent-rs/target/x86_64-unknown-linux-musl/release/surveyscan-agent agent-rs/target/x86_64-unknown-linux-musl/release/surveyscan-portable .dist/rust/linux/
	cp agent-rs/target/x86_64-pc-windows-gnu/release/surveyscan-agent.exe agent-rs/target/x86_64-pc-windows-gnu/release/surveyscan-portable.exe .dist/rust/windows/
	cd .dist/rust && sha256sum linux/* windows/* > SHA256SUMS
# Пакеты (C52.04): deb, rpm, tar.gz, MSI и zip агента (Rust) и collector (Go) в .dist/packages; нужны make build, make rust,
# nfpm и wixl (msitools)
packages:
	python3 scripts/packages.py --version $(VERSION)

test:
	$(GO) test -mod=readonly -count=1 -p 2 ./...
vet:
	$(GO) vet -mod=readonly ./...
fmt-check:
	test -z "$$($$($(GO) env GOROOT)/bin/gofmt -l cmd internal contracts)"
contracts:
	mkdir -p .local
	$(CONTRACT_PYTHON) ../docs/plans/surveyscan-v2/contracts/C03/checks/validate_contracts.py .local/contracts-validation.json
integration:
	GO=$(GO) python3 scripts/dev.py integration
dev-up: build
	python3 scripts/dev.py up
dev-down:
	python3 scripts/dev.py down
verify: fmt-check vet test contracts
