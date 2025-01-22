CLANG = clang
GO = env GOOS=linux go

BPF_DIR = ebpf-receiver/ebpf
GO_DIR = otelcol-ebpf-demo
BPF_SRC = $(BPF_DIR)/http.bpf.c
BPF_OBJ = $(BPF_DIR)/http.o
GO_SRC = $(GO_DIR)/main.go
GO_OBJ = opentelemetry-collector

build: build-collector build-ebpf build-daemon
build-collector:
	./ocb --config builder-config.yaml
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

clean:
	rm -f $(BPF_OBJ)
	cd $(GO_DIR) && $(GO) clean