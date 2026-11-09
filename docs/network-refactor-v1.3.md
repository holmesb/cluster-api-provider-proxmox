# Networking refactor

Upstream references: [PR 779](https://github.com/ionos-cloud/cluster-api-provider-proxmox/pull/779)
(network model and renderers; no associated issue), and
[issue 868](https://github.com/ionos-cloud/cluster-api-provider-proxmox/issues/868)
([PR 869](https://github.com/ionos-cloud/cluster-api-provider-proxmox/pull/869)) for explicit false defaults.

This batch follows upstream's shared network model, parsed routes and routing policies, cloud-init and
Ignition renderers, and optional `is6` API fields. API and v1alpha1 conversion changes are included with
explicit approval. The fork's PCI allocation, storage selection, VM recovery and IPAM behavior are retained.

`pkg/network` replaces `pkg/types` as the shared network model. Default gateways become explicit routes
rather than properties of individual IP addresses. Route destinations and policy selectors are parsed
into `net/netip` values before rendering. VRF members are represented by names in `Children`, and routing
tables can be unset. Cloud-init and Ignition share structural validation and expose renderer interfaces.

The optional `is6` boolean selects IPv6 when true and IPv4 when false. It is needed for a `default` or
`all` placeholder whose family cannot be inferred from a concrete gateway or policy selector. Existing
concrete IPv4/IPv6 destinations and gateways do not generally require the field. The webhook rejects
ambiguous placeholders without a family hint. Explicit `defaultIPv4: false` or `defaultIPv6: false` is
also preserved by the updated upstream defaulting logic.

Validation now detects route collisions by destination, metric and effective routing table, including
VRF membership. It rejects policies that mix IPv4 and IPv6 selectors. Networks still require a default
route or DHCP somewhere. A secondary static interface can omit a gateway when another interface supplies
one. These checks apply to rendered network data as well as API webhook validation.

The generated machine and machine-template CRDs each gain four optional `is6` schema entries. Removing
those new entries produces CRDs identical to the previous versions; the fork-specific fields remain.
Deploy the regenerated CRDs with the updated controller and webhook. Conversion tests cover omitted,
false and true `is6` values for routes and policies on additional interfaces and VRFs, for both machines
and machine templates.

## Before deployment

Check the existing custom resources in the `ic` repository against the updated schema and validation,
including ClusterClass variables, patches and rendered machine templates. Repeat this check if the
configuration changes before deployment.

The initial read-only audit of scratch, test and tools found single-NIC definitions without explicit
routes, routing policies or VRFs. The corresponding live snapshot contained 16 machines, 10 machine
templates and three infrastructure clusters, with no complex network definitions. All 16 allocated
machine network definitions passed offline rendering with both cloud-init and Ignition. The audit used
existing IPAM allocations and synthetic MAC addresses and did not change any live resources.

After deployment, rebuild scratch and verify IP allocation, bootstrap networking, node registration,
Cilium and RBAC. Separately validate multi-NIC, dual-stack and VRF configurations before relying on the
refactor for those topologies; scratch only exercises its current single-NIC IPv4 network.
