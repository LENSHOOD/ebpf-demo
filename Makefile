CLANG = clang
GO = env GOOS=linux go

BPF_DIR = ebpf
GO_DIR = daemon
BPF_SRC = $(BPF_DIR)/http.bpf.c
BPF_OBJ = $(BPF_DIR)/http.o
GO_SRC = $(GO_DIR)/main.go
GO_OBJ = ebpf-demo

build: build-ebpf build-daemon
build-ebpf: $(BPF_OBJ)
build-daemon: $(GO_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	@echo "Building eBPF program..."
	$(CLANG) -g -O2 -target bpf -c $(BPF_SRC) -o $(BPF_OBJ)

$(GO_OBJ): $(GO_SRC)
	@echo "Building user-space daemon..."
	cd $(GO_DIR) && $(GO) build -o $(GO_OBJ)

clean:
	rm -f $(BPF_OBJ)
	cd $(GO_DIR) && $(GO) clean