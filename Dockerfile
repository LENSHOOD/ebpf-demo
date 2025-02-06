FROM ubuntu:22.04

WORKDIR /app

RUN mkdir -p ebpf-receiver/ebpf/ & mkdir -p otelcol-ebpf-demo & mkdir -p db_init & mkdir -p collector-config
COPY otelcol-ebpf-demo/ebpf-demo-collector otelcol-ebpf-demo/

EXPOSE 8000

CMD ["./otelcol-ebpf-demo/ebpf-demo-collector", "--config", "./collector-config/config.yaml"]