FROM ubuntu:22.04

WORKDIR /app

RUN mkdir -p ebpf-receiver/ebpf/ & mkdir -p otelcol-ebpf-demo & mkdir -p db_init
COPY ebpf-receiver/ebpf/tcp.o ebpf-receiver/ebpf/
COPY otelcol-ebpf-demo/ebpf-demo-collector otelcol-ebpf-demo/
COPY config.yaml .
COPY pg-exporter/db_init/init.sql db_init/

EXPOSE 8000

CMD ["./otelcol-ebpf-demo/ebpf-demo-collector", "--config", "config.yaml"]