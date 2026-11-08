/*
Copyright 2023-2026 IONOS Cloud.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vmservice

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	lutherproxmox "github.com/luthermonson/go-proxmox"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/cluster-api/util/conditions"

	infrav1 "github.com/ionos-cloud/cluster-api-provider-proxmox/api/v1alpha2"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox"
)

func TestReconcileVirtualMachineConfig_ExistingCPUAndPCIDevices(t *testing.T) {
	machineScope, _, _ := setupReconcilerTestWithCondition(t,
		infrav1.ProxmoxMachineVirtualMachineProvisionedCloningReason)
	machineScope.ProxmoxMachine.Spec.NumSockets = ptr.To(int32(2))
	machineScope.ProxmoxMachine.Spec.NumCores = ptr.To(int32(4))
	machineScope.ProxmoxMachine.Spec.PCIDevices = []infrav1.PCIDeviceSpec{{Mapping: "gpu"}}
	vm := newStoppedVM()
	require.NoError(t, json.Unmarshal([]byte(`{
		"description":"test", "sockets":2, "cores":4, "hostpci0":"mapping=gpu,pcie=1"
	}`), vm.VirtualMachineConfig))
	machineScope.SetVirtualMachine(vm)

	requeue, err := reconcileVirtualMachineConfig(context.Background(), machineScope)
	require.NoError(t, err)
	require.False(t, requeue)
	require.Equal(t, infrav1.ProxmoxMachineVirtualMachineProvisionedWaitingForDiskReconciliationReason,
		conditions.GetReason(machineScope.ProxmoxMachine, infrav1.ProxmoxMachineVirtualMachineProvisionedCondition))
}

func TestReconcileAdditionalVolumes_ExistingDeviceMaps(t *testing.T) {
	for _, slot := range []string{"scsi1", "sata1", "ide1", "virtio1"} {
		t.Run(slot, func(t *testing.T) {
			machineScope, _, _ := setupReconcilerTest(t)
			machineScope.ProxmoxMachine.Spec.Disks = &infrav1.Storage{
				AdditionalVolumes: []infrav1.DiskSpec{{Disk: slot, SizeGB: 10}},
			}
			cfg := &lutherproxmox.VirtualMachineConfig{}
			require.NoError(t, json.Unmarshal([]byte(fmt.Sprintf(`{"%s":"ssd_a:vm-123-disk-1"}`, slot)), cfg))
			var options []proxmox.VirtualMachineOption

			require.NoError(t, reconcileAdditionalVolumes(context.Background(), machineScope, cfg, &options))
			require.Empty(t, options, "an existing disk must not be allocated again")
		})
	}
}

func TestReconcileAdditionalVolumes_ReuseUnusedDeviceMap(t *testing.T) {
	machineScope, _, _ := setupReconcilerTest(t)
	machineScope.ProxmoxMachine.Spec.Disks = &infrav1.Storage{
		AdditionalVolumes: []infrav1.DiskSpec{{Disk: "scsi1", SizeGB: 10, Storage: ptr.To("ssd_a")}},
	}
	cfg := &lutherproxmox.VirtualMachineConfig{}
	require.NoError(t, json.Unmarshal([]byte(`{
		"unused1":"ssd_a:vm-123-disk-2", "unused0":"ssd_a:vm-123-disk-1",
		"unused2":"ssd_b:vm-123-disk-3"
	}`), cfg))
	var options []proxmox.VirtualMachineOption

	require.NoError(t, reconcileAdditionalVolumes(context.Background(), machineScope, cfg, &options))
	require.Equal(t, []proxmox.VirtualMachineOption{{Name: "scsi1", Value: "ssd_a:vm-123-disk-1"}}, options)
}
