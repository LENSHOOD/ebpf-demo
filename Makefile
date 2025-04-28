include .env
export

DOCKER = sudo docker
KBCTL = sudo kubectl

GO_ENV = env GOOS=linux
GO = $(GO_ENV) go
GO_DIR = otelcol-ebpf-demo

CLANG = clang
BPF_DIR = ebpf-receiver/ebpf
BPF_SRC = $(BPF_DIR)/l4_traffic.bpf.c
BPF_OBJ = $(BPF_DIR)/l4_traffic.o

build-in-container: clean
	$(DOCKER) build -t ebpf-demo-builder:latest -f Dockerfile.build .
	$(DOCKER) run --rm -v ./:/build -w /build ebpf-demo-builder:latest make build

build: build-ebpf build-collector
build-collector:
	$(GO_ENV) ./ocb --config builder-config.yaml
build-ebpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	@echo "Building eBPF program..."
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -c $(BPF_SRC) -o $(BPF_OBJ)

.PHONY: build run-local build-image deploy destroy setup-example destroy-example clean print-kustomization
run-local:
	$(GO) run ./$(GO_DIR) --config config.yaml

build-image:
	$(DOCKER) build -t $(IMAGE_NAME):$(IMAGE_TAG) .
	$(DOCKER) tag $(IMAGE_NAME):$(IMAGE_TAG) $(DOCKER_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	$(DOCKER) push $(DOCKER_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

print-kustomization:
	envsubst < kustomization.yaml | cat -

deploy:
	envsubst < kustomization.yaml | $(KBCTL) apply -k -

destroy:
	envsubst < kustomization.yaml | $(KBCTL) delete -k -

setup-example:
	$(KBCTL) apply -k ./example/

destroy-example:
	$(KBCTL) delete -k ./example/

clean:
	rm -f $(BPF_OBJ)
	cd $(GO_DIR) && $(GO) clean