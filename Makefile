include .env
export

DOCKER = docker
KBCTL = sudo kubectl

GO_ENV = env GOOS=linux
GO = $(GO_ENV) go
GO_DIR = otelcol-ebpf-demo

CLANG = clang
BPF_DIR = ebpf-receiver/ebpf
BPF_SRC = $(BPF_DIR)/l4_traffic.bpf.c
BPF_OBJ = $(BPF_DIR)/l4_traffic.o

ARCH := $(shell uname -m)

ifeq ($(ARCH),x86_64)
	OCB := ./ocb-linux-amd64
else ifeq ($(ARCH),aarch64)
	OCB := ./ocb-linux-arm64
else
	$(error ❌ Unsupported architecture: $(ARCH))
endif

build-in-container: 
	$(DOCKER) build -t ebpf-demo-builder:latest -f Dockerfile.build .
	$(DOCKER) run --rm -v ./:/build -w /build ebpf-demo-builder:latest make build

dev-in-container:
	$(DOCKER) build -t ebpf-demo-builder:latest -f Dockerfile.build .
	$(DOCKER) run -it --rm -v ./:/build -w /build ebpf-demo-builder:latest /bin/bash

BUILD_CONFIG = builder-config.yaml
build: build-ebpf build-collector
build-collector:
	$(GO_ENV) ${OCB} --config $(BUILD_CONFIG)
build-ebpf: $(BPF_OBJ)
build-collector-debug: 
	$(GO_ENV) ${OCB} --ldflags="" --gcflags="all=-N -l" --verbose --config $(BUILD_CONFIG)

$(BPF_OBJ): $(BPF_SRC)
	@echo "Building eBPF program..."
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -c $(BPF_SRC) -o $(BPF_OBJ)

CONFIG = config.yaml
run-local:
	$(GO) run ./$(GO_DIR) --config $(CONFIG)

build-image:
	$(DOCKER) build -t $(IMAGE_NAME):$(IMAGE_TAG) .
	$(DOCKER) tag $(IMAGE_NAME):$(IMAGE_TAG) $(DOCKER_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	$(DOCKER) push $(DOCKER_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

build-image-debug:
	$(DOCKER) build -t $(IMAGE_NAME):$(IMAGE_TAG) -f Dockerfile.debug .
	$(DOCKER) tag $(IMAGE_NAME):$(IMAGE_TAG) $(DOCKER_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	$(DOCKER) push $(DOCKER_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

print-kustomization:
	envsubst < kustomization.tpl | cat -

deploy:
	envsubst < kustomization.tpl > kustomization.yaml
	$(KBCTL) apply -k .
	rm -f kustomization.yaml

destroy:
	envsubst < kustomization.tpl > kustomization.yaml
	$(KBCTL) delete -k .
	rm -f kustomization.yaml

setup-example:
	$(KBCTL) apply -k ./example/

destroy-example:
	$(KBCTL) delete -k ./example/

clean:
	rm -f $(BPF_OBJ)
	cd $(GO_DIR) && $(GO) clean

.PHONY: build run-local build-image deploy destroy setup-example destroy-example clean print-kustomization
