# IPAM claim resolution and address-status recovery

This batch adapts upstream issue
[758](https://github.com/ionos-cloud/cluster-api-provider-proxmox/issues/758), implemented by
[PR 794](https://github.com/ionos-cloud/cluster-api-provider-proxmox/pull/794) (`5ec6b09`) and
[PR 799](https://github.com/ionos-cloud/cluster-api-provider-proxmox/pull/799) (`1d42da8`).

Static IP provisioning looks up the expected claim by machine name, interface, and pool offset, then
follows the claim's address reference. It no longer scans every address in a pool or assumes the address
and claim have the same name. The expected claim names are unchanged, so existing valid allocations can
be reused. Claim annotations are merged into a copy of the address without changing cached objects.

The resolver distinguishes missing, pending, resolved, and conflicting claims. Provisioning creates a
missing claim and waits for allocation. Pending claims are left in place. Conflicts leave the machine
waiting for static IP allocation with a diagnostic condition; they do not trigger automatic deletion or
reassignment of IPAM objects. A deterministic orphan address is reported and ignored until a claim exists.

Additional checks strengthen the upstream implementation. The claim owner must match the machine's
nonempty UID, name, kind, and API group, including references to older API versions. The address must also
refer back to the expected claim. A claim from a previous machine with the same name, or an address bound
to a different claim, cannot be consumed. Both the claim and address must reference the expected pool.
Invalid IP address strings are rejected as conflicts before status recovery can attempt to parse them.

Address collection preserves all requested offsets when a pool is used repeatedly. The corrected IPv6
default-pool condition prevents additional pools from becoming default addresses merely because the
interface has a default IPv6 address. Existing network settings and bootstrap rendering are preserved.

For a running VM whose `status.ipAddresses` is empty, reconciliation can restore interface addresses and
machine addresses from existing allocations. Recovery does not create or update claims or addresses,
change the VM, or advance provisioning conditions. Every expected claim must resolve before any address
status is published. Missing, pending, conflicting, or orphaned allocations leave status untouched.
Recovery is skipped when IP status is already populated; repairing partial status is outside this batch.

No API schema changes or IPAM object migrations are required. Rebuild scratch after deployment to verify
new claims and node registration. Validate restore recovery in a controlled environment with intact
claims and addresses before relying on it for a management-cluster restore. Do not remove live address
allocations as a validation step.
