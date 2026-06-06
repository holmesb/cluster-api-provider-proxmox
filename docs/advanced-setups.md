## Advanced Setups

To get started with CAPMOX please refer to the [Getting Started](Usage.md#quick-start) section.

## Multiple NICs

If you want to create VMs with multiple network devices,
You will need to create `InClusterPool` or `GlobalInClusterPool` to manage IPs.

here is a `GlobalInClusterPool` example:

```yaml
apiVersion: ipam.cluster.x-k8s.io/v1alpha2
kind: GlobalInClusterIPPool
metadata:
  name: shared-inclusterippool
spec:
  addresses: ${SECONDARY_IP_RANGES}
  prefix: ${SECONDARY_IP_PREFIX}
  gateway: ${SECONDARY_GATEWAY}
```

In the cluster template flavor=multiple-vlans you can define a secondary network device for the VMs.
To do that you will need to set extra environment variables along with the required ones:

```bash
# The secondary IP ranges for Cluster nodes
export SECONDARY_IP_RANGES="[10.10.10.100-10.10.10.150]"
# The Subnet Mask in CIDR notation for your node secondary IP ranges
export SECONDARY_IP_PREFIX=24
# The secondary gateway for the machines network-config
export SECONDARY_GATEWAY="10.10.10.254"
# The secondary dns nameservers for the machines network-config
export SECONDARY_DNS_SERVERS="[8.8.8.8, 8.8.4.4]"
# The Proxmox secondary network bridge for VMs
export SECONDARY_BRIDGE=vmbr2
```

### Multiple gateways
If you have multiple gateways (especially without VRF devices), you may
want to control gateway selection by inserting metrics.
For this purpose, you can add a metric annotation to your pools:

```yaml
apiVersion: ipam.cluster.x-k8s.io/v1alpha2
kind: GlobalInClusterIPPool
metadata:
  annotations:
    ipam.capmox.cluster.x-k8s.io/gateway-metric: "200"
  name: shared-inclusterippool
spec:
  addresses: ${SECONDARY_IP_RANGES}
  prefix: ${SECONDARY_IP_PREFIX}
  gateway: ${SECONDARY_GATEWAY}
```
This annotation will be used when creating a netplan definition for a VM.

The metric of the default gateway can be controlled with the proxmoxcluster definition:
```yaml
[...]
    ipv4Config:
      addresses:
      - 10.10.0.70-10.10.0.79
      gateway: 10.10.0.1
      metric: 100
      prefix: 24
```

Metrics are, like all network configuration, part of bootstrap, and will not reconcile.

#### Generate a Cluster

```bash
clusterctl generate cluster test-multiple-vlans  \
  --infrastructure proxmox \
  --kubernetes-version v1.33.3  \
  --control-plane-machine-count=1 \
  --worker-machine-count=2 \
  --flavor=multiple-vlans > cluster.yaml
```

## Dual Stack

Regarding dual-stack support, you can use the following environment variables to define the IPv6 ranges for the VMs:

```bash
# The IPv6 ranges for Cluster nodes
export NODE_IPV6_RANGES="[2001:db8:1::1-2001:db8:1::10]"
# The Subnet Mask in CIDR notation for your node IPv6 ranges
export IPV6_PREFIX=64
# The ipv6 gateway for the machines network-config.
export IPV6_GATEWAY="2001:db8:1::1"
```

If you're using cilium, be aware that cilium's helm chart requires `ipv6.enabled=true` to actually support IPv6 pod- and service networks.

## IPv6 only cluster

Clusters without IPv4 are possible, but require kube-vip to be newer than 0.7.1 (version 0.7.0 probably works, but we did not test it).

If you're using cilium, be aware that Cilium's helm chart requires `ipv6.enabled=true` to actually support IPv6 pod- and service networks.


#### Generate a Cluster

```bash
clusterctl generate cluster test-dual-stack  \
  --infrastructure proxmox \
  --kubernetes-version v1.33.3  \
  --control-plane-machine-count=1 \
  --worker-machine-count=2 \
  --flavor=dual-stack > cluster.yaml
```


## Cluster with LoadBalancer nodes

The template for LoadBalancers is for [dual stack](##dual-stack) with [multiple nics](##multiple-nics). All
environment variables regarding those need to be set. You may want to reduce the template to your use case.

The idea is that there are special nodes for load balancing. These have an extra network card which is supposed
to be connected to the BGP receiving switches. All services exposed with the type "LoadBalancer" will take an
IP from `METALLB_IPV4_RANGE` or `METALLB_IPV6_RANGE` which will be announced to the BGP peers.

The template presupposes two bgp peers per address family (ipv4,ipv6) because this is a high availability setup.

For the routing to work, we employ source ip based routing. This does not work (reliably) without source IPs.
For this reason, all nodes are created with `ipvs` in kube-proxy. This necessitates also setting `strictARP`,
as otherwise packets may still take wrong paths and cause reverse path filter issues.

If you require changing `METALLB_IPV{4,6}_RANGE` after a cluster has been deployed, you need to redeploy load balancer
nodes, as these variables are also used in bootstrap to establish source ip based routing.

LoadBalancer nodes are tainted and only run pods required for load balancing.

```
## -- loadbalancer nodes -- #
LOAD_BALANCER_MACHINE_COUNT: 2                                # Number of load balancer nodes
EXT_SERVICE_BRIDGE: "vmbr2"                                   # The network bridge device used for load balancing and bgp.
LB_BGP_IPV4_RANGES: "[172.16.4.10-172.16.4.20]"               # The IP ranges used by the cluster for establishing the bgp session.
LB_BGP_IPV6_RANGES:
LB_BGP_IPV4_PREFIX: "24"                                      # Subnet Mask in CIDR notation for your bgp IP ranges.
LB_BGP_IPV6_PREFIX:
METALLB_IPV4_ASN: "65400"                                     # The nodes bgp asn.
METALLB_IPV6_ASN:
METALLB_IPV4_BGP_PEER: "172.16.4.1"                           # The nodes bgp peer IP address.
METALLB_IPV4_BGP_PEER2: "172.16.4.2"                          # Backup bgp peer for H/A
METALLB_IPV6_BGP_PEER:
METALLB_IPV6_BGP_PEER2:
METALLB_IPV4_BGP_SECRET: "REDACTED"                           # The secret required to establish a bgp session (if any).
METALLB_IPV6_BGP_SECRET:
METALLB_IPV4_BGP_PEER_ASN: "65500"                            # The bgp peer's asn.
METALLB_IPV4_BGP_PEER2_ASN:                                   # Backup bgp peer's asn
METALLB_IPV6_BGP_PEER_ASN:
METALLB_IPV6_BGP_PEER2_ASN:
METALLB_IPV4_RANGE: 7.6.5.0/24                                # The IP Range MetalLB uses to announce your services.
METALLB_IPV6_RANGE:
```

#### Generate a Cluster

```bash
clusterctl generate cluster test-bgp-lb  \
  --infrastructure proxmox \
  --kubernetes-version v1.33.3  \
  --control-plane-machine-count=1 \
  --worker-machine-count=2 \
  --flavor=cilium-load-balancer > cluster.yaml
```

#### Node over-/ underprovisioning

By default our scheduler only allows to allocate as much memory to guests as the host has. This might not be desirable behaviour in all cases. For example, one might explicitly want to overprovision their host's memory, or to reserve a bit of the host's memory for itself.

This behaviour can be configured in the `ProxmoxCluster` CR through the field `.spec.schedulerHints.memoryAdjustment`.

For example, setting it to `0` (zero), entirely disables scheduling based on memory. Alternatively, if you set it to any value greater than `0`, the scheduler will treat your host as it would have `${value}%` of memory. In real numbers that would mean, if you have a host with 64 GB of memory and set the number to `300`, the scheduler would allow you to provision guests with a total of 192GB memory and therefore overprovision the host. (Use with caution! It's strongly suggested to have memory ballooning configured everywhere.) Or, if you were to set it to `95` for example, it would treat your host as it would only have 60.8 GB of memory, and leave the remaining 3.2 GB for the host.

## Template lookup based on Proxmox tags
CAPMOX can clone VMs from Proxmox templates selected by tags instead of by `sourceNode` and `templateID`.

Tag-based lookup is enabled by setting `templateSelector.matchTags` on a `ProxmoxMachine`, or through the provided ClusterClasses.
For example, you can set the `TEMPLATE_TAGS="tag1,tag2"` environment variable when using the `auto-image` template.

```yaml
spec:
  templateSelector:
    matchTags: ["capmox", "ubuntu-24.04", "k8s-1.33"]
    matchPolicy: bestSubset
```

### Tag matching policies
Template selection is controlled by `templateSelector.matchTags` and `templateSelector.matchPolicy`.

`matchTags` is the list of tags CAPMOX looks for on Proxmox VM templates. `matchPolicy` controls how the template's
tags are compared with `matchTags`. If `matchPolicy` is omitted, CAPMOX uses its default matching policy.

Supported values are:
* `exact`: the template's tags must exactly match `matchTags`. The template must have all requested tags and no additional tags.
* `uniqueSubset`: the template must contain all requested `matchTags`, but may have additional tags. Provisioning fails if more than one template matches.
* `bestSubset`: the template must contain all requested `matchTags`, but may have additional tags. If multiple templates match, CAPMOX selects the template with the fewest additional tags. Provisioning fails if no template matches, or if there is no single best match.

For example, given `matchTags: ["capmox", "ubuntu-24.04"]`:

| Template tags | `exact` | `uniqueSubset` | `bestSubset` |
| --- | --- | --- | --- |
| `capmox, ubuntu-24.04` | matches | matches | preferred match |
| `capmox, ubuntu-24.04, k8s-1.33` | does not match | matches | lower priority than the exact tag set |
| `capmox, ubuntu-24.04, k8s-1.33, gpu` | does not match | matches | lower priority than the two rows above |
| `capmox, ubuntu-22.04` | does not match | does not match | does not match |

### Shared versus local template storage
The `localStorage` setting changes the scope in which CAPMOX expects to find matching templates.

#### `localStorage: false` — default
Use this when templates are stored on shared Proxmox storage.

CAPMOX expects the selected template to be accessible from any node that may host the VM. For policies that require a
unique result, only one template should match across the Proxmox cluster.

Provisioning fails if:
* no template matches the requested tags;
* more than one template matches when the selected `matchPolicy` requires uniqueness;
* the selected template is not accessible from the chosen node.

#### `localStorage: true`
Use this when each Proxmox node has its own local copy of the template. Each node listed in `allowedNodes` is expected 
to have a matching local template. This allows the same template tags to be reused on multiple nodes, as long as the 
tag matching policy resolves to a valid template on each node.

Provisioning fails if:
* any node in `allowedNodes` has no matching template;
* any node in `allowedNodes` has ambiguous matches for the selected `matchPolicy`;
* the matched templates are not equivalent for your intended workload.

The VM still uses the node-local storage pool chosen by the scheduler unless `.spec.storage` or per-volume `storage` is
set explicitly.

### Storage selection
CAPMOX can either use explicit storage pools you configure, or automatically select a suitable pool on the chosen Proxmox node.

#### Explicit storage (unchanged)
If you set `.spec.storage` on a `ProxmoxMachine`, or `storage` on an additional volume, that value is used as-is for 
cloning and volume creation. In that case, no automatic storage selection is performed.

#### Automatic storage selection (overview)
If no storage is specified at machine level (`.spec.storage` empty) and no per-volume `storage` is set, the provider will:

1. Select a node for the VM using the existing scheduler (memory- and replica-aware behaviour described earlier in this document).
2. On that node, list all storages and filter to pools that are:
    * enabled and active,
    * not shared (`shared=false`),
    * and whose `content` includes `images`.
3. For each candidate pool, compute an **effective free capacity**:
   * Start from the pool's *virtual* free capacity (derived from Proxmox storage content, e.g. thin-provisioned backends) when available, otherwise fall back to the pool's reported free bytes (`avail`).
   * Subtract the sizes of auto-selected additional volumes from **other** `ProxmoxMachine`s on the same node that:
     * are not Ready yet,
     * have their persisted `status.storageSelection.additionalStorage` set to that pool, and
     * do not override storage at machine or volume level.
   * This behaves like a "soft reservation" so that new machines are biased towards pools that are not already committed to large additional volumes from other pending machines.
4. Derive a **boot storage** pool and an **additional storage** pool for that machine.

This storage selection is **persisted per `ProxmoxMachine`** in its status. As long as the VM stays on the same node and the disks spec does not change, the same boot/additional pools are reused across reconciles for that machine, even if other machines are created and storage utilisation changes.

If no eligible pools are found, storage selection fails and the machine reconcile will surface an error.

#### Automatic storage selection (additional volumes)
For additional volumes (defined under `.spec.disks.additionalVolumes`):

* If `storage` is set on the volume, that value is used.
* Otherwise, if `.spec.storage` is set on the machine, that value is used.
* Otherwise (no storage anywhere), CAPMOX uses the **machine’s persisted storage selection**:
  * When the selection is first computed, CAPMOX:
  * Determines the **largest additional volume size** requested on that machine.
  * Selects the first candidate pool (by effective free capacity) that has **enough free bytes to fit that volume**.
    * Persists this as the machine’s `additionalStorage` pool in status.
  * All auto-selected additional volumes on that machine then use this persisted `additionalStorage` pool.

If no candidate pool has sufficient capacity to fit the largest additional volume, reconcile fails with an error indicating that no local image-capable storage on that node can fit the requested additional volumes.

This means that for a given machine, the automatically chosen pool for additional volumes is stable over time and will not change just because other workloads are created later. CAPMOX does not move existing volumes between pools if a "better" pool appears afterwards.

#### Automatic storage selection (boot volume)
For the boot/clone volume (when `.spec.storage` is empty):

* On the initial selection, CAPMOX will:
  * Try to place the boot volume on a **different pool** from the additional volumes, as long as:
  * That pool is one of the eligible node-local image-capable pools, and
  * It has enough free capacity to fit the boot volume.
* If no such alternative pool exists (or the boot size is not known), the boot volume will use the same pool as the additional volumes.
* The chosen boot storage pool is then **persisted in status** alongside the additional storage pool and reused for subsequent reconciles of that machine.

This means, in the common case where multiple local pools exist and both boot and data disks are large:

* Additional volumes are placed on the pool with the **most effective free capacity** that can fit the largest additional volume at the time the machine is first reconciled.
* The boot volume is placed on another pool that can also fit its size, when such a pool exists, to help spread I/O across pools.
* Subsequent changes in cluster storage utilisation do **not** change the boot/additional pool choices for that existing machine.

If you want to avoid this behaviour for a particular machine, set `.spec.storage` explicitly, or specify `storage` on your additional volumes.

### Template lookup and ClusterClasses
With the ClusterClasses provided in this repository, there are two ways to tell CAPMOX which Proxmox VM template to clone.

#### Selector mode — tag-based lookup
Selector mode is recommended for multi-node setups.
```yaml
spec:
  topology:
    variables:
      - name: templateSelector
        value:
          matchTags: ["capmox", "ubuntu-24.04", "k8s-1.33"]
          matchPolicy: bestSubset
```

When `templateSelector.matchTags` is set, CAPMOX uses tag-based lookup. Do not set `sourceNode` or `templateID` for the
same machine template. If using local, non-shared template storage, also set `localStorage: true`:
```yaml
spec:
  topology:
    variables:
      - name: localStorage
        value: true
```

See the `localStorage` section above for the lookup behaviour and failure conditions.

#### Explicit mode — source node and template ID
Explicit mode is the default if `templateSelector` is not set.

```yaml
spec:
  topology:
    variables:
      - name: cloneSpec
        value:
          machineSpec:
            controlPlane:
              sourceNode: pve1
              templateID: 100
            workerNode:
              sourceNode: pve1
              templateID: 100
            loadBalancer:
              sourceNode: pve1
              templateID: 100
```

In explicit mode, CAPMOX clones the specified template ID from the specified Proxmox node. `localStorage` is not used in
this mode because placement is already pinned by `sourceNode`.

## GPU passthrough using Proxmox PCI Resource Mappings
CAPMOX can attach PCI devices to VMs by referencing **Proxmox PCI Resource Mappings** ("mapped devices"), rather than 
hard-coding PCI addresses.

### Supply: create Proxmox PCI mappings
Create one Proxmox PCI [Resource Mapping](https://pve.proxmox.com/wiki/QEMU/KVM_Virtual_Machines#resource_mapping) per 
physical device. CAPMOX expects each mapping to include the below description field containing `;` separated key/value 
pairs. Example `description` (single line):

```
class=gpu;model_key=10de:1234;chip=ExampleGPUChip;product=Example GPU Product Name
```
* `class` is a device type (eg `gpu`).
* `model_key` is a stable PCI **vendor ID:device ID** identifier (as commonly shown by tools like `lspci -nn`). Can also find vendor/device IDs at https://devicehunt.com/ or https://pci-ids.ucw.cz/.
* `chip` / `product` are informational for human intuition, aren't compulsory, nor relied on for CAPMOX selection.

All fields are case-insensitive (can be either upper or lower).

### Demand: request PCI devices from a machine
A `ProxmoxMachine` (or template) can request PCI devices via `pciDeviceRequests`. Example request for “any GPU”:

```yaml
kind: ProxmoxMachine
spec:
  pciDeviceRequests:
    - name: gpu
      count: 1
      selector:
        matchLabels:
          class: gpu
```

Example request for a specific GPU model:
```yaml
kind: ProxmoxMachine
spec:
  pciDeviceRequests:
    - name: gpu
      count: 1
      selector:
        matchLabels:
          class: gpu
          model_key: "10de:1234"  # vendor ID:device ID - see https://devicehunt.com/ or lspci -nn
```

Notes:
* `model_key` contains `:` because by default in PCI notation, these are represented as **vendor ID:device ID**. CAPMOX matches selectors against above `description` fields case-insensitively.
* Placement is **claim-driven**: CAPMOX binds a `ProxmoxPCIDeviceClaim` to a free mapping first, then places the VM on the Proxmox node that owns that mapping.
* CAPMOX uses Kubernetes **Lease** objects internally as the lock for each Proxmox mapping ID. Leases prevent two claims from binding the same mapping concurrently (race-free allocation) and are created/deleted automatically by the controller.

### Demand: request GPU workers in ClusterClass
Currently, ClusterClasses only support the GPU PCI device type. GPU passthrough is achieved using per-MachineDeployment 
overrides. We avoid maintaining multiple per-GPU model MachineDeploymentClasses, CAPMOX has a single GPU worker class 
and users can specify an override variable per MachineDeployment. CAPMOX ClusterClasses have a variable:
```yaml
kind: ClusterClass
spec:
  topology:
    variables:
      - name: gpuModelKey
        required: false
        schema:
          openAPIV3Schema:
            type: string
```

The `gpuModelKey` variable drives a ClusterClass patch to the GPU worker MachineDeploymentClass:
```yaml
kind: ClusterClass
spec:
  topology:
    patches:
      - name: gpu-model-key
        enabledIf: "{{ if .gpuModelKey }}true{{ end }}"
        definitions:
          - selector:
              apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
              kind: ProxmoxMachineTemplate
              matchResources:
                machineDeploymentClass:
                  names: ["proxmox-worker-gpu"]
            jsonPatches:
              - op: add
                path: /spec/template/spec/pciDeviceRequests/0/selector/matchLabels/model_key
                valueFrom:
                  variable: gpuModelKey
```

In your Cluster, you can define multiple GPU MachineDeployments. They can be of two types: generic and model-specific. 
Both use the **same MachineDeploymentClass**. Former will select any GPU PCIe device for which a Proxmox Resource 
Mapping exists (see above). Latter contains a `gpuModelKey` override specifying the GPU model you'd  like these workers 
to use:
```yaml
kind: Cluster
spec:
  topology:
    workers:
      machineDeployments:
        - class: proxmox-worker-gpu
          name: worker-gpu-generic
          replicas: 2
        - class: proxmox-worker-gpu
          name: worker-gpu-model-1234
          replicas: 2
          variables:
            overrides:
              - name: gpuModelKey
                value: "10de:1234"  # vendor ID:device ID - see https://devicehunt.com/ or lspci -nn
```
In above case, two worker nodes will be created with any available GPU, and two with a "10de:1234" model. Any number of 
specific GPU model machineDeployments can be requested this way, all using the same `proxmox-worker-gpu` 
MachineDeploymentClass.

With this configuration, each `ProxmoxMachineTemplate` created by the ClusterClass will use tag-based template lookup. The selected `matchPolicy` controls whether the match must be exact, unique, or the best subset match.

## Proxmox RBAC with least privileges
For the Proxmox API user/token you create for CAPMOX, these are the minimum required permissions.

### Prerequisites

* Create a role called `Sys.Audit` with the `Sys.Audit` permission and a role called `Datastore.AllocateSpace` with the `Datastore.AllocateSpace` permission only. Apart from these roles, we only need the built-in roles.
* Create a pool for the VMs created and managed by CAPMOX (called `capi` in the example).
* Create a pool for the templates used by CAPMOX (called `templates` in the example) and assign all templates that should be accessible by CAPMOX to this pool.

### Privileges

| Path                                 | Role                    | Propagate |
| ------------------------------------ | ----------------------- | --------- |
| `/`                                  | Sys.Audit               | false     |
| `/nodes`                             | Sys.Audit               | true      |
| `/pool/capi`                         | PVEVMAdmin              | false     |
| `/pool/templates`                    | PVETemplateUser         | false     |
| `/sdn/zones/localnetwork/vmbr0/1234` | PVESDNUser              | false     |
| `/storage/capi_files`                | PVEDataStoreAdmin       | false     |
| `/storage/shared_block`              | Datastore.AllocateSpace | false     |

* In the SDN example, `1234` is the optional VLAN ID if you want to restrict the user to a specific VLAN.
* CAPMOX needs `PVEDataStoreAdmin` on a storage suitable for ISO images for cloud-init. Create a dedicated storage for this (you can use subdirectories in an existing network share for example).
* CAPMOX needs `AllocateSpace` permissions on a storage suitable for disc images. This can be shared with other users as it is only accessed indirectly by cloning/deleting VMs.

## Proxmox TLS communication

The default behavior of the Proxmox API is to skip TLS verification when communicating with the Proxmox API,
The `PROXMOX_INSECURE` environment variable is set to `true` by default in the CAPMOX manager, to skip the verification of the TLS certificate with the Proxmox API.
```
containers:
  - name: manager
    args:
    - --leader-elect
    - --feature-gates=ClusterTopology=true
    - "--diagnostics-address=:8443"
    - "--insecure-diagnostics=false"
    - "--v=0"
    env:
    - name: PROXMOX_INSECURE
      value: "true"
```

If you want to use a certificate for communication with the Proxmox API, you can set the `proxmox-root-cert-file` flag variable to the path of the certificate file, and
set the `PROXMOX_INSECURE` environment variable to `false`.

```yaml
containers:
  - name: manager
    args:
    - --leader-elect
    - --feature-gates=ClusterTopology=true
    - "--diagnostics-address=:8443"
    - "--insecure-diagnostics=false"
    - "--v=0"
    - "--proxmox-root-cert-file=/var/lib/proxmox/certs/root-ca.pem"
    env:
    - name: PROXMOX_INSECURE
      value: "false"
    volumeMounts:
    - name: proxmox-root-cert
      mountPath: /var/lib/proxmox/certs
      readOnly: true

volumes:
  - name: proxmox-root-cert
    secret:
      secretName: proxmox-root-cert

```


## Custom Allowed Nodes for ProxmoxMachine

Previously, the Proxmox nodes that will host the Machines are defined in `ProxmoxCluster.spec.allowedNodes`, that config restrict us from placing some set of machines into some specific nodes.
Now, you can also define and override the `allowedNodes` in the ProxmoxMachine, to do so:

```diff
kind: ProxmoxMachineTemplate
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
metadata:
  name: "test-control-plane"
spec:
  template:
    spec:
       sourceNode: "pve"
       templateID: 1000
       format: "qcow2"
       full: true
+      allowedNodes: ["pve-1", "pve-3", "pve-4"]
```

With the following config, you can override what has been set in the Proxmox Cluster, and also you have more flexibility for example you can have a custom allowed Nodes per Machine Deployments.

## Custom Default Network IP Pool for ProxmoxMachine

Like the Allowed Nodes, in the past we couldn't set a custom IP Pool for the default network device, everything was tied to the ProxmoxCluster IP Config.
Now, you can also customize the IP Pool for the default network device, just by setting the `ipv4PoolRef` and/or `ipv6PoolRef`.

```diff
kind: ProxmoxMachineTemplate
apiVersion: infrastructure.cluster.x-k8s.io/v1alpha1
metadata:
  name: "test-control-plane"
spec:
  template:
    spec:
     sourceNode: "pve"
     templateID: 1000
     format: "qcow2"
     full: true
     network:
       default:
         bridge: ${BRIDGE}
         model: virtio
+        ipv4PoolRef:
+          apiGroup: ipam.cluster.x-k8s.io
+          kind: GlobalInClusterIPPool
+          name: shared-inclusterippool
```

You can set either `ipv4PoolRef` or `ipv6PoolRef` or you can also set them both for dual-stack.
It's up for you also to manage the IP Pool, you can choose a `GlobalInClusterIPPool` or an `InClusterIPPool`.

## Notes

* Clusters with IPV6 only is supported.
* Multiple NICs & Dual-stack setups can be mixed together.
* If you're looking for more customized setups, you can create your own cluster template and use it with the `clusterctl generate cluster` command, by passing it `--from yourtemplate.yaml`.

## API Reference

Please refer to the API reference:
* [CAPMOX API Reference](https://doc.crds.dev/github.com/ionos-cloud/cluster-api-provider-proxmox).
