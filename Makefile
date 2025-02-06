DOCKER = sudo docker
KBCTL = sudo kubectl
CLANG = clang
GO_ENV = env GOOS=linux
GO = $(GO_ENV) go
GO_DIR = otelcol-ebpf-demo

BPF_DIR = ebpf-receiver/ebpf
BPF_SRC = $(BPF_DIR)/tcp.bpf.c
BPF_OBJ = $(BPF_DIR)/tcp.o

build: build-ebpf build-collector
build-collector:
	$(GO_ENV) ./ocb --config builder-config.yaml
build-ebpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	@echo "Building eBPF program..."
	$(CLANG) -g -O2 -target bpf -c $(BPF_SRC) -o $(BPF_OBJ)

.PHONY: run-local build-image deploy clean
run-local:
	$(GO) run ./$(GO_DIR) --config config.yaml

build-image:
	$(DOCKER) build -t otel-ebpf-demo:latest .
	$(DOCKER) tag otel-ebpf-demo:latest localhost:5000/otel-ebpf-demo:latest
	$(DOCKER) push localhost:5000/otel-ebpf-demo:latest

deploy:
	$(KBCTL) apply -k .

clean:
	rm -f $(BPF_OBJ)
	cd $(GO_DIR) && $(GO) clean