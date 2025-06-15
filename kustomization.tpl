apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: otel-demo

resources:
  - deploy/sa_role.yaml
  - deploy/daemonset.yaml
  - deploy/svc.yaml

images:
  - name: ebpf-demo-collector-image
    newName: ${DOCKER_REGISTRY}/${IMAGE_NAME}
    newTag: ${IMAGE_TAG}

configMapGenerator:
  - name: collector-config
    files:
      - config.yaml=${CONFIG_FILE}
  - name: ebpf-bin-traffic
    files:
      - ebpf-receiver/ebpf/l4_traffic.o
  - name: ebpf-bin-pid
    files:
      - ebpf-receiver/ebpf/quad_tuple_pid.o
  - name: db-init
    files:
      - pg-exporter/db_init/init.sql
