# VM race and recovery fixes

These changes adapt five upstream fixes to the fork's VM lifecycle. PCI placement, storage selection,
additional volumes, and the existing handling of temporarily unnamed clones are preserved.

| Fix | Upstream commit |
| --- | --- |
| Recover controller-allocated VMID collisions | `675d663` |
| Read current ProxmoxMachine state before cloning | `9d48963` |
| Wait for boot disk resize before further configuration | `82f725e` |
| Wait for active VM tasks and the target's clone lock | `64dc57e` |
| Retry bootstrap ISO upload and attachment errors | `70e193a` |

Before creating a clone, the controller reads the ProxmoxMachine directly from the Kubernetes API server.
It waits if that object already records a VM ID or task. This avoids creating another VM when the cached
object predates a previous reconciliation's clone request. The read is a safeguard against stale state,
not an atomic reservation across independent controllers.

Boot disk resize tasks are recorded in `status.taskRef`, and provisioning pauses until they finish.
Before changing a stopped, unprovisioned VM, the controller also checks Proxmox for active tasks and the
target VM's clone lock. This protects against a lost task reference; clone tasks belong to the source
template and do not appear in the target VM's active task list. Failure to list active tasks is reported
and retried rather than allowing configuration to continue.

A VMID collision is recoverable only when the controller marked the ID as allocated and the machine
has not yet acquired a provider ID. Recovery releases the stale node location and clears the allocated
ID so a later reconciliation can choose another. It does not modify or delete the foreign VM. Explicitly
assigned IDs and already-adopted VMs retain their existing behavior. Proxmox's empty and temporary
`VM <id>` names are treated as clone initialization lag, rather than as collisions.

ISO upload and attachment failures leave the machine waiting for bootstrap data and return an error
for the controller's normal retry backoff. As upstream implements it, there is no retry-count limit or
overall deadline in this path. It retries while reconciliation remains enabled unless the operation
succeeds or the machine is deleted. This includes persistent Proxmox API errors; it does not classify
individual HTTP statuses. ISO rendering errors remain terminal provisioning failures.

Restoring lost IP address status after a management-cluster restore is separate work. That upstream fix
depends on IPAM changes outside this batch.

After deployment, rebuild scratch and check for one VM per machine, correct CPU, memory, disks, NICs,
and successful node registration. Separately exercise a machine with PCI allocation and additional
volumes, since scratch does not cover those features. Fault-injection scenarios need a controlled test:
hold a clone or configuration task open, delay disk resize, fail ISO upload or attachment once, and
simulate a controller-allocated VMID collision without changing an unrelated VM.
