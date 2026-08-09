REGISTRY ?= noeio
TAG ?= $(shell date +%Y%m%d%H%M)-$(shell git rev-parse --short=7 HEAD)
PLATFORM ?= linux/amd64,linux/arm64

.PHONY: build

build:
ifndef MODEL
	$(error MODEL is required, e.g. make build MODEL=noeio-derp)
endif
	docker buildx build --platform $(PLATFORM) -f build/$(MODEL)/Dockerfile -t $(REGISTRY)/$(MODEL):$(TAG) --push .
