FROM ubuntu:22.04

WORKDIR /app

RUN mkdir -p ebpf-receiver/ebpf/ & mkdir -p otelcol-ebpf-demo
COPY ebpf-receiver/ebpf/tcp.o ebpf-receiver/ebpf/
COPY otelcol-ebpf-demo/opentelemetry-collector otelcol-ebpf-demo/
COPY config.yaml .

EXPOSE 8000

CMD ["./otelcol-ebpf-demo/opentelemetry-collector", "--config", "config.yaml"]