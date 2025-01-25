DOCKER = sudo docker
KBCTL = sudo kubectl
CLANG = clang
GO_ENV = env GOOS=linux
GO = $(GO_ENV) go

BPF_DIR = ebpf-receiver/ebpf
GO_DIR = otelcol-ebpf-demo
BPF_SRC = $(BPF_DIR)/tcp.bpf.c
BPF_OBJ = $(BPF_DIR)/tcp.o
GO_SRC = $(GO_DIR)/main.go
GO_OBJ = opentelemetry-collector

build: build-collector build-ebpf build-daemon
build-collector:
	$(GO_ENV) ./ocb --config builder-config.yaml
build-ebpf: $(BPF_OBJ)
build-daemon: $(GO_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	@echo "Building eBPF program..."
	$(CLANG) -g -O2 -target bpf -c $(BPF_SRC) -o $(BPF_OBJ)

$(GO_OBJ): $(GO_SRC)
	@echo "Building user-space daemon..."
	cd $(GO_DIR) && $(GO) build -o $(GO_OBJ)

run:
	$(GO) run ./$(GO_DIR) --config config.yaml

build-image:
	$(DOCKER) build -t otel-ebpf-demo:latest .
	$(DOCKER) tag otel-ebpf-demo:latest localhost:5000/otel-ebpf-demo:latest
	$(DOCKER) push localhost:5000/otel-ebpf-demo:latest

deploy:
	$(KBCTL) apply -f deploy.yaml

clean:
	rm -f $(BPF_OBJ)
	cd $(GO_DIR) && $(GO) clean