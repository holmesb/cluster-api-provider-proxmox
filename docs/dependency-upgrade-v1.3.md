# Dependency upgrade on release/v1.3.0

This dependency refresh follows upstream CAPMOX v0.9.2 (`0691ffd`). It keeps the fork's PCI allocation,
storage selection, additional volumes, and ClusterClass configuration.

| Component | Previous | Updated |
| --- | --- | --- |
| Go | 1.25.10 | 1.26.10 |
| Cluster API libraries | 1.11.8 | 1.12.11 |
| Kubernetes libraries | 0.33.3 effective version | 0.34.11 |
| controller-runtime | 0.21.0 | 0.22.5 |
| IPAM provider in-cluster libraries | 1.0.3 | 1.1.0 |
| go-proxmox | 0.5.1 | 0.8.2 |
| controller-gen | 0.18.0 | 0.19.0 |
| golangci-lint | 2.9.0 | 2.11.4 |

The E2E configuration pins CAPI core, kubeadm bootstrap, and kubeadm control-plane providers to 1.12.11,
the in-cluster IPAM provider to 1.1.0, and workload Kubernetes to 1.34.11. Envtest uses Kubernetes 1.34.0.
Coordinate deployed provider and clusterctl upgrades separately; changing Go dependencies does not upgrade
the controllers already running in the management cluster. Existing CAPMOX v1alpha2 manifests remain valid.

The go-proxmox upgrade replaces indexed VM configuration fields with device maps. CAPMOX now reads those
maps for network devices, PCI attachments, occupied disk slots, and unused disks. Existing PCI devices and
additional volumes must remain attached without creating duplicate configuration or disks.

CRDs must be regenerated and deployed with the controller. The controller-gen version annotations change,
and the embedded CAPI endpoint schema no longer requires both `host` and `port` to be supplied initially.
The v1alpha1 conversion implementation and the fork's API fields are unchanged.

After deployment, validate creation and deletion of a scratch cluster, then exercise a machine with PCI
allocation and additional volumes. Confirm correct node/template selection, CPU settings, disk placement,
bootstrap networking, and successful registration of all nodes before upgrading other clusters.
