REGISTRY ?= noeio

# version.txt is the single source of truth, kept in sync by version.sh.
VERSION ?= $(shell cat version.txt)
BUILD_DATE ?= $(shell date +%Y%m%d%H%M)
GIT_ID ?= $(shell git rev-parse --short=7 HEAD)

# Set IS_LATEST=true to tag the image as `latest` instead of a versioned tag.
IS_LATEST ?= false
TAG ?= $(if $(filter true,$(IS_LATEST)),latest,v$(VERSION)-$(BUILD_DATE)-$(GIT_ID))

PLATFORM ?= linux/amd64,linux/arm64
PLATFORMS ?= linux-amd64 linux-arm64 macos-amd64 macos-aarch64 windows-amd64

# Forward optional container build settings to the binary build script.
export RUST_IMAGE BUILD_IMAGE BUILD_CACHE

.PHONY: build binaries

build:
ifndef MODEL
	$(error MODEL is required, e.g. make build MODEL=noeio-derp)
endif
	docker buildx build --platform $(PLATFORM) -f build/$(MODEL)/Dockerfile -t $(REGISTRY)/$(MODEL):$(TAG) --push .

# Build the cross-compilation image, then compile noeio inside Docker.
binaries:
	./scripts/build-binaries.sh $(PLATFORMS)
