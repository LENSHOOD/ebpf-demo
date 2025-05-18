apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: kube-system

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
      - config.yaml
  - name: ebpf-bin
    files:
      - ebpf-receiver/ebpf/l4_traffic.o
  - name: db-init
    files:
      - pg-exporter/db_init/init.sql
