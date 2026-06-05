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

// Package vmservice implement Proxmox vm logic.
package vmservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	"sigs.k8s.io/cluster-api/util"
	"sigs.k8s.io/cluster-api/util/conditions"

	infrav1 "github.com/ionos-cloud/cluster-api-provider-proxmox/api/v1alpha2"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/internal/inject"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/internal/service/scheduler"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/internal/service/taskservice"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox/goproxmox"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/scope"
)

const (
	// See the following link for a list of available config options:
	// https://pve.proxmox.com/pve-docs/api-viewer/index.html#/nodes/{node}/qemu/{vmid}/config

	optionSockets     = "sockets"
	optionCores       = "cores"
	optionMemory      = "memory"
	optionTags        = "tags"
	optionDescription = "description"
)

// ErrNoVMIDInRangeFree is returned if no free VMID is found in the specified vmIDRange.
var ErrNoVMIDInRangeFree = errors.New("No free vmid found in vmIDRange")

// ReconcileVM makes sure that the VM is in the desired state by:
//  1. Creating the VM if it does not exist, then...
//  2. Updating the VM with the bootstrap data, such as the cloud-init meta and user data, before...
//  3. Powering on the VM, and finally...
//  4. Returning the real-time state of the VM to the caller
func ReconcileVM(ctx context.Context, scope *scope.MachineScope) (infrav1.VirtualMachine, error) {
	// Initialize the result.
	vm := infrav1.VirtualMachine{
		Name:  scope.Name(),
		State: infrav1.VirtualMachineStatePending,
	}

	// If there is an in-flight task associated with this VM then do not
	// reconcile the VM until the task is completed.
	if inFlight, err := taskservice.ReconcileInFlightTask(ctx, scope); err != nil || inFlight {
		return vm, err
	}
	scope.Logger.V(4).Info("proxmox machine state", "state", conditions.GetReason(scope.ProxmoxMachine, infrav1.ProxmoxMachineVirtualMachineProvisionedCondition))

	// TODO: This requires a proper state machine. We're reusing
	// the condition reasons in VirtualMachineProvisioned as a state machine
	// for convenience, but this definitely needs to be refactored.
	if requeue, err := ensureVirtualMachine(ctx, scope); err != nil || requeue {
		return vm, err
	} // VirtualMachineProvisioned reason is Cloning

	if requeue, err := reconcileVirtualMachineConfig(ctx, scope); err != nil || requeue {
		scope.Logger.V(4).Info("after reconcileVirtualMachineConfig", "machineName", scope.ProxmoxMachine.GetName(), "requeue", requeue, "err", err)
		return vm, err
	} // VirtualMachineProvisioned reason is WaitingForDiskReconciliation

	if err := reconcileDisks(ctx, scope); err != nil {
		scope.Logger.V(4).Info("after reconcileDisks", "machineName", scope.ProxmoxMachine.GetName(), "err", err)
		return vm, err
	} // VirtualMachineProvisioned reason is WaitingForStaticIPAllocation

	if requeue, err := reconcileIPAddresses(ctx, scope); err != nil || requeue {
		scope.Logger.V(4).Info("after reconcileIPAddresses", "machineName", scope.ProxmoxMachine.GetName(), "requeue", requeue, "err", err)
		return vm, err
	} // VirtualMachineProvisioned reason is WaitingForBootstrapData

	if requeue, err := reconcileBootstrapData(ctx, scope); err != nil || requeue {
		scope.Logger.V(4).Info("after reconcileBootstrapData", "machineName", scope.ProxmoxMachine.GetName(), "requeue", requeue, "err", err)
		return vm, err
	} // VirtualMachineProvisioned reason is WaitingForVMPowerUp

	if requeue, err := reconcilePowerState(ctx, scope); err != nil || requeue {
		scope.Logger.V(4).Info("after reconcilePowerState", "machineName", scope.ProxmoxMachine.GetName(), "requeue", requeue, "err", err)
		return vm, err
	} // VirtualMachineProvisioned reason is WaitingForClusterAPIMachineAddresses

	if err := reconcileMachineAddresses(scope); err != nil {
		scope.Logger.V(4).Info("after reconcileMachineAddresses", "machineName", scope.ProxmoxMachine.GetName(), "err", err)
		return vm, err
	} // VirtualMachineProvisioned reason is WaitingForCloudInit

	if requeue, err := checkCloudInitStatus(ctx, scope); err != nil || requeue {
		scope.Logger.V(4).Info("after checkCloudInitStatus", "machineName", scope.ProxmoxMachine.GetName(), "requeue", requeue, "err", err)
		return vm, err
	} // VirtualMachineProvisioned reason is WaitingForBootstrapReady

	// handle invalid state of the machine
	if proxmoxMachineHasVMProvisionFailedReason(scope) {
		scope.Logger.V(4).Info("invalid proxmoxmachine state", "state", conditions.GetReason(scope.ProxmoxMachine, infrav1.ProxmoxMachineVirtualMachineProvisionedCondition))
		// If you end up here, please file a bug report.
		return vm, errors.New("invalid state (failed and no error)")
	}

	// if the root machine is ready, we can assume that the VM is ready as well.
	// unmount the cloud-init iso if it is still mounted.
	if conditions.IsTrue(scope.Machine, clusterv1.AvailableCondition) && scope.Machine.Status.NodeRef.IsDefined() {
		if err := unmountCloudInitISO(ctx, scope); err != nil {
			return vm, errors.Wrapf(err, "failed to unmount cloud-init iso for vm %s", scope.Name())
		}
	} // State Machine is finished
	scope.Logger.V(4).Info("condition", "condition", conditions.GetReason(scope.ProxmoxMachine, infrav1.ProxmoxMachineVirtualMachineProvisionedCondition))

	vm.State = infrav1.VirtualMachineStateReady
	return vm, nil
}

func proxmoxMachineHasVMProvisionFailedReason(scope *scope.MachineScope) bool {
	reason := conditions.GetReason(scope.ProxmoxMachine, infrav1.ProxmoxMachineVirtualMachineProvisionedCondition)
	return reason == infrav1.ProxmoxMachineVirtualMachineProvisionedVMProvisionFailedReason ||
		reason == infrav1.ProxmoxMachineVirtualMachineProvisionedTaskFailedReason
}

func hostPCISlotValue(cfg any, index int) string {
	if cfg == nil || index < 0 {
		return ""
	}
	cfgValue := reflect.ValueOf(cfg)
	if cfgValue.Kind() == reflect.Pointer {
		cfgValue = cfgValue.Elem()
	}
	if !cfgValue.IsValid() {
		return ""
	}
	// Field names depend on the Proxmox client struct. Try the common variants.
	candidates := []string{
		fmt.Sprintf("Hostpci%d", index),
		fmt.Sprintf("HostPCI%d", index),
	}
	for _, fieldName := range candidates {
		fieldValue := cfgValue.FieldByName(fieldName)
		if !fieldValue.IsValid() || fieldValue.Kind() != reflect.String {
			continue
		}
		return strings.TrimSpace(fieldValue.String())
	}
	return ""
}

func desiredHostPCISpecOptions(pciDevices []infrav1.PCIDeviceSpec) []proxmox.VirtualMachineOption {
	if len(pciDevices) == 0 {
		return nil
	}

	// Keep hostpciN assignment deterministic even if the list order changes.
	devices := slices.Clone(pciDevices)
	sort.Slice(devices, func(i, j int) bool { return devices[i].Mapping < devices[j].Mapping })

	opts := make([]proxmox.VirtualMachineOption, 0, len(devices))
	for i, dev := range devices {
		pcie := ptr.Deref(dev.PCIExpress, true)
		value := fmt.Sprintf("mapping=%s,pcie=%d", dev.Mapping, boolToInt(pcie))
		opts = append(opts, proxmox.VirtualMachineOption{Name: fmt.Sprintf("hostpci%d", i), Value: value})
	}
	return opts
}

func desiredHostPCIDevices(scope *scope.MachineScope) []infrav1.PCIDeviceSpec {
	pm := scope.ProxmoxMachine
	merged := make([]infrav1.PCIDeviceSpec, 0)
	seen := map[string]struct{}{}

	// Prefer allocations from claims first.
	for _, allocation := range pm.Status.PCIDeviceAllocations {
		mapping := strings.TrimSpace(allocation.Mapping)
		if mapping == "" {
			continue
		}
		if _, ok := seen[mapping]; ok {
			continue
		}
		seen[mapping] = struct{}{}
		merged = append(merged, infrav1.PCIDeviceSpec{Mapping: mapping, PCIExpress: allocation.PCIExpress})
	}

	// Then include any explicitly pinned devices.
	for _, device := range pm.Spec.PCIDevices {
		mapping := strings.TrimSpace(device.Mapping)
		if mapping == "" {
			continue
		}
		if _, ok := seen[mapping]; ok {
			continue
		}
		seen[mapping] = struct{}{}
		merged = append(merged, device)
	}

	return merged
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// diskSlotOccupied reports whether a VM disk slot, for example "scsi1", is already set in the VM config.
func diskSlotOccupied(cfg any, slot string) bool {
	if cfg == nil || slot == "" {
		return false
	}

	slot = strings.TrimSpace(strings.ToLower(slot))
	var fieldName string
	switch {
	case strings.HasPrefix(slot, "scsi"):
		fieldName = "SCSI" + slot[4:]
	case strings.HasPrefix(slot, "sata"):
		fieldName = "SATA" + slot[4:]
	case strings.HasPrefix(slot, "ide"):
		fieldName = "IDE" + slot[3:]
	case strings.HasPrefix(slot, "virtio"):
		fieldName = "VirtIO" + slot[6:]
	default:
		// Unknown bus: assume occupied to avoid creating junk config keys.
		return true
	}

	cfgValue := reflect.ValueOf(cfg)
	if cfgValue.Kind() == reflect.Pointer {
		cfgValue = cfgValue.Elem()
	}
	if !cfgValue.IsValid() {
		return false
	}

	fieldValue := cfgValue.FieldByName(fieldName)
	if !fieldValue.IsValid() || fieldValue.Kind() != reflect.String {
		return false
	}
	return strings.TrimSpace(fieldValue.String()) != ""
}

func checkCloudInitStatus(ctx context.Context, machineScope *scope.MachineScope) (requeue bool, err error) {
	if conditions.GetReason(machineScope.ProxmoxMachine, infrav1.ProxmoxMachineVirtualMachineProvisionedCondition) != infrav1.ProxmoxMachineVirtualMachineProvisionedWaitingForCloudInitReason {
		// Machine is in the wrong state to reconcile, we only reconcile machines waiting for cloud init
		return false, nil
	}

	if !machineScope.SkipQemuGuestCheck() {
		if err := machineScope.InfraCluster.ProxmoxClient.QemuAgentStatus(ctx, machineScope.VirtualMachine); err != nil {
			return true, errors.Wrap(err, "error waiting for agent")
		}
	}

	// TODO: Is there a status for Ignition?
	if !machineScope.SkipCloudInitCheck() {
		if running, err := machineScope.InfraCluster.ProxmoxClient.CloudInitStatus(ctx, machineScope.VirtualMachine); err != nil || running {
			if running {
				return true, nil
			}
			if errors.Is(goproxmox.ErrCloudInitFailed, err) {
				conditions.Set(machineScope.ProxmoxMachine, metav1.Condition{
					Type:    infrav1.ProxmoxMachineVirtualMachineProvisionedCondition,
					Status:  metav1.ConditionFalse,
					Reason:  infrav1.ProxmoxMachineVirtualMachineProvisionedVMProvisionFailedReason,
					Message: err.Error(),
				})
			}
			return false, err
		}
	}

	conditions.Set(machineScope.ProxmoxMachine, metav1.Condition{
		Type:   infrav1.ProxmoxMachineVirtualMachineProvisionedCondition,
		Status: metav1.ConditionFalse,
		Reason: infrav1.ProxmoxMachineVirtualMachineProvisionedWaitingForBootstrapReadyReason,
	})
	return false, nil
}

// ensureVirtualMachine creates a Proxmox VM if it doesn't exist and updates the given MachineScope.
func ensureVirtualMachine(ctx context.Context, machineScope *scope.MachineScope) (requeue bool, err error) {
	// if there's an associated task, requeue.
	if machineScope.ProxmoxMachine.Status.TaskRef != nil {
		return true, nil
	}

	// Initialize the state machine for proxmox machine deployment.
	// NOTE: We are setting this condition only in case it does not exist, so we avoid to get flickering LastConditionTime
	// in case of cloning errors or powering on errors.
	if !conditions.Has(machineScope.ProxmoxMachine, infrav1.ProxmoxMachineVirtualMachineProvisionedCondition) ||
		conditions.GetReason(machineScope.ProxmoxMachine, infrav1.ProxmoxMachineVirtualMachineProvisionedCondition) == clusterv1.WaitingForClusterInfrastructureReadyReason ||
		conditions.GetReason(machineScope.ProxmoxMachine, infrav1.ProxmoxMachineVirtualMachineProvisionedCondition) == clusterv1.WaitingForBootstrapDataReason {
		conditions.Set(machineScope.ProxmoxMachine, metav1.Condition{
			Type:   infrav1.ProxmoxMachineVirtualMachineProvisionedCondition,
			Status: metav1.ConditionFalse,
			Reason: infrav1.ProxmoxMachineVirtualMachineProvisionedCloningReason,
		})
	}

	// Before going further, we need the VM's managed object reference.
	vmRef, err := FindVM(ctx, machineScope)

	// TODO: Codeflow
	if err != nil {
		switch {
		case errors.Is(err, ErrVMNotFound):
			if err := updateVMLocation(ctx, machineScope); err != nil {
				return false, errors.Wrap(err, "error trying to locate vm")
			}

			// we always want to trigger reconciliation at this point.
			return false, err
		case errors.Is(err, ErrVMNotInitialized):
			return true, err
		case !errors.Is(err, ErrVMNotCreated):
			return false, err
		}

		// Create the VM.
		resp, err := createVM(ctx, machineScope)
		if err != nil {
			// Only set CloningFailed if createVM didn't already set a terminal
			// failure reason (e.g. VMProvisionFailed for insufficient resources).
			if conditions.GetReason(machineScope.ProxmoxMachine, infrav1.ProxmoxMachineVirtualMachineProvisionedCondition) != infrav1.ProxmoxMachineVirtualMachineProvisionedVMProvisionFailedReason {
				conditions.Set(machineScope.ProxmoxMachine, metav1.Condition{
					Type:    infrav1.ProxmoxMachineVirtualMachineProvisionedCondition,
					Status:  metav1.ConditionFalse,
					Reason:  infrav1.ProxmoxMachineVirtualMachineProvisionedCloningFailedReason,
					Message: err.Error(),
				})
			}
			return false, err
		}
		machineScope.Logger.V(4).Info("Task created", "taskID", resp.Task.ID)

		// make sure spec.VirtualMachineID is always set.
		machineScope.ProxmoxMachine.Status.TaskRef = ptr.To(string(resp.Task.UPID))
		machineScope.SetVirtualMachineID(resp.NewID)

		// requeue until cloning is finished
		return true, nil
	}

	// make sure spec.providerID is always set.
	biosUUID := extractUUID(vmRef.VirtualMachineConfig.SMBios1)
	machineScope.SetProviderID(biosUUID)

	// setting the VirtualMachine object for completing the reconciliation.
	machineScope.SetVirtualMachine(vmRef)

	// at this point the VM is found, so err must be nil
	return false, nil
}

func reconcileDisks(ctx context.Context, machineScope *scope.MachineScope) error {
	if conditions.GetReason(machineScope.ProxmoxMachine, infrav1.ProxmoxMachineVirtualMachineProvisionedCondition) != infrav1.ProxmoxMachineVirtualMachineProvisionedWaitingForDiskReconciliationReason {
		// Machine is in the wrong state to reconcile, we only reconcile Cloning VMs
		return nil
	}

	machineScope.V(4).Info("reconciling disks")
	disks := machineScope.ProxmoxMachine.Spec.Disks

	if disks != nil {
		vm := machineScope.VirtualMachine
		if vm.IsRunning() || ptr.Deref(machineScope.ProxmoxMachine.Status.Initialization.Provisioned, false) {
			// We only want to do this before the machine was started or is ready
			return nil
		}

		if bv := disks.BootVolume; bv != nil {
			if _, err := machineScope.InfraCluster.ProxmoxClient.ResizeDisk(ctx, vm, bv.Disk, bv.FormatSize()); err != nil {
				machineScope.Error(err, "unable to set disk size", "vm", machineScope.VirtualMachine.VMID)
				return err
			}
		}
	}

	// Machine is now waiting for IPAddress Allocations, move State Machine along
	conditions.Set(machineScope.ProxmoxMachine, metav1.Condition{
		Type:   infrav1.ProxmoxMachineVirtualMachineProvisionedCondition,
		Status: metav1.ConditionFalse,
		Reason: infrav1.ProxmoxMachineVirtualMachineProvisionedWaitingForStaticIPAllocationReason,
	})
	return nil
}

func reconcileVirtualMachineConfig(ctx context.Context, machineScope *scope.MachineScope) (requeue bool, err error) {
	if conditions.GetReason(machineScope.ProxmoxMachine, infrav1.ProxmoxMachineVirtualMachineProvisionedCondition) != infrav1.ProxmoxMachineVirtualMachineProvisionedCloningReason {
		// Machine is in the wrong state to reconcile, we only reconcile Cloning VMs.
		return false, nil
	}

	if machineScope.VirtualMachine.IsRunning() || ptr.Deref(machineScope.ProxmoxMachine.Status.Initialization.Provisioned, false) {
		// We only want to do this before the machine was started or is ready
		return false, nil
	}

	vmConfig := machineScope.VirtualMachine.VirtualMachineConfig

	// CPU & Memory
	var vmOptions []proxmox.VirtualMachineOption
	sockets := ptr.Deref(machineScope.ProxmoxMachine.Spec.NumSockets, 0)
	cores := ptr.Deref(machineScope.ProxmoxMachine.Spec.NumCores, 0)
	memory := ptr.Deref(machineScope.ProxmoxMachine.Spec.MemoryMiB, 0)
	if sockets > 0 && vmConfig.Sockets != int(sockets) {
		vmOptions = append(vmOptions, proxmox.VirtualMachineOption{Name: optionSockets, Value: sockets})
	}
	if cores > 0 && vmConfig.Cores != int(cores) {
		vmOptions = append(vmOptions, proxmox.VirtualMachineOption{Name: optionCores, Value: cores})
	}
	if memory > 0 && int(vmConfig.Memory) != int(memory) {
		vmOptions = append(vmOptions, proxmox.VirtualMachineOption{Name: optionMemory, Value: memory})
	}

	// Description
	if machineScope.ProxmoxMachine.Spec.Description != nil {
		if machineScope.VirtualMachine.VirtualMachineConfig.Description != *machineScope.ProxmoxMachine.Spec.Description {
			vmOptions = append(vmOptions, proxmox.VirtualMachineOption{Name: optionDescription, Value: machineScope.ProxmoxMachine.Spec.Description})
		}
	}

	// Network vmbrs.
	if machineScope.ProxmoxMachine.Spec.Network != nil && shouldUpdateNetworkDevices(machineScope) {
		devices := machineScope.ProxmoxMachine.Spec.Network.NetworkDevices
		for _, v := range devices {
			vmOptions = append(vmOptions, proxmox.VirtualMachineOption{
				Name:  string(v.Name),
				Value: formatNetworkDevice(ptr.Deref(v.Model, "virtio"), ptr.Deref(v.Bridge, ""), v.MTU, v.VLAN, v.Queues),
			})
		}
	}

	// custom tags
	if machineScope.ProxmoxMachine.Spec.Tags != nil {
		machineScope.VirtualMachine.SplitTags()
		length := len(machineScope.VirtualMachine.VirtualMachineConfig.TagsSlice)
		for _, tag := range machineScope.ProxmoxMachine.Spec.Tags {
			if !machineScope.VirtualMachine.HasTag(tag) {
				machineScope.VirtualMachine.VirtualMachineConfig.TagsSlice = append(machineScope.VirtualMachine.VirtualMachineConfig.TagsSlice, tag)
			}
		}
		if len(machineScope.VirtualMachine.VirtualMachineConfig.TagsSlice) > length {
			vmOptions = append(vmOptions, proxmox.VirtualMachineOption{Name: optionTags, Value: strings.Join(machineScope.VirtualMachine.VirtualMachineConfig.TagsSlice, ";")})
		}
	}

	// PCI devices (hostpciN).
	if desired := desiredHostPCISpecOptions(desiredHostPCIDevices(machineScope)); len(desired) > 0 {
		for _, opt := range desired {
			idx := -1
			_, _ = fmt.Sscanf(strings.TrimPrefix(opt.Name, "hostpci"), "%d", &idx)
			current := hostPCISlotValue(vmConfig, idx)
			if current != opt.Value {
				vmOptions = append(vmOptions, opt)
			}
		}
	}

	if err := reconcileAdditionalVolumes(ctx, machineScope, vmConfig, &vmOptions); err != nil {
		return false, err
	}

	if len(vmOptions) == 0 {
		return false, nil
	}

	machineScope.V(4).Info("reconciling virtual machine config")

	task, err := machineScope.InfraCluster.ProxmoxClient.ConfigureVM(ctx, machineScope.VirtualMachine, vmOptions...)
	if err != nil {
		return false, errors.Wrapf(err, "failed to configure VM %s", machineScope.Name())
	}

	machineScope.ProxmoxMachine.Status.TaskRef = ptr.To(string(task.UPID))

	conditions.Set(machineScope.ProxmoxMachine, metav1.Condition{
		Type:   infrav1.ProxmoxMachineVirtualMachineProvisionedCondition,
		Status: metav1.ConditionFalse,
		Reason: infrav1.ProxmoxMachineVirtualMachineProvisionedWaitingForDiskReconciliationReason,
	})
	return true, nil
}

func reconcileAdditionalVolumes(ctx context.Context, machineScope *scope.MachineScope, vmConfig any, vmOptions *[]proxmox.VirtualMachineOption) error {
	disksSpec := machineScope.ProxmoxMachine.Spec.Disks
	if disksSpec == nil || len(disksSpec.AdditionalVolumes) == 0 {
		return nil
	}

	findMatchingUnusedVolume := func(cfg any, storageName string) string {
		if cfg == nil || storageName == "" {
			return ""
		}

		cfgValue := reflect.ValueOf(cfg)
		if cfgValue.Kind() == reflect.Pointer {
			cfgValue = cfgValue.Elem()
		}
		if !cfgValue.IsValid() {
			return ""
		}

		cfgType := cfgValue.Type()
		for i := 0; i < cfgType.NumField(); i++ {
			fieldMetadata := cfgType.Field(i)
			if !strings.HasPrefix(fieldMetadata.Name, "Unused") {
				continue
			}

			fieldValue := cfgValue.Field(i)
			if !fieldValue.IsValid() || fieldValue.Kind() != reflect.String {
				continue
			}

			volID := strings.TrimSpace(fieldValue.String())
			if volID != "" && strings.HasPrefix(volID, storageName+":") {
				return volID
			}
		}
		return ""
	}

	pendingInReconcile := map[string]struct{}{}

	var (
		defaultAdditionalStorage string
		defaultStoragesResolved  bool
	)

	var nodeName string
	if machineScope.ProxmoxMachine.Status.ProxmoxNode != nil {
		nodeName = strings.TrimSpace(*machineScope.ProxmoxMachine.Status.ProxmoxNode)
	}

	for _, vol := range disksSpec.AdditionalVolumes {
		slotName := strings.ToLower(strings.TrimSpace(vol.Disk))
		if slotName == "" {
			return errors.New("additional volume disk slot must not be empty")
		}

		alreadySet := diskSlotOccupied(vmConfig, slotName)
		machineScope.V(4).Info("additionalVolume: slot state", "machine", machineScope.Name(), "slot", slotName, "occupied", alreadySet)
		if alreadySet {
			if pendingGuardEnabled {
				clearPending(machineScope, slotName)
			}
			continue
		}

		if pendingGuardEnabled && isPending(machineScope, slotName) {
			machineScope.V(4).Info("additionalVolume: skip, pending add in effect", "machine", machineScope.Name(), "slot", slotName)
			continue
		}

		if _, seen := pendingInReconcile[slotName]; seen {
			machineScope.V(4).Info("additionalVolume: skip, add already queued in this reconcile", "machine", machineScope.Name(), "slot", slotName)
			continue
		}

		var storageName string
		if vol.Storage != nil && *vol.Storage != "" {
			storageName = *vol.Storage
		} else if machineScope.ProxmoxMachine.Spec.Storage != nil && *machineScope.ProxmoxMachine.Spec.Storage != "" {
			storageName = *machineScope.ProxmoxMachine.Spec.Storage
		} else {
			if !defaultStoragesResolved {
				if nodeName == "" {
					return errors.New("unable to auto-select storage for additionalVolumes: Proxmox node is unknown")
				}

				var err error
				_, defaultAdditionalStorage, err = ensureStorageSelection(ctx, machineScope, nodeName)
				if err != nil {
					return err
				}
				defaultStoragesResolved = true
			}

			storageName = defaultAdditionalStorage
		}

		machineScope.V(4).Info("additionalVolume: resolved storage", "machine", machineScope.Name(), "slot", slotName, "storage", storageName)
		volumeValue := findMatchingUnusedVolume(vmConfig, storageName)
		if volumeValue != "" {
			machineScope.V(4).Info("additionalVolume: reattaching existing unused volume", "machine", machineScope.Name(), "slot", slotName, "volumeID", volumeValue)
		} else if vol.Format != nil && *vol.Format != "" {
			volumeValue = fmt.Sprintf("%s:0,size=%dG,format=%s", storageName, vol.SizeGB, string(*vol.Format))
			machineScope.Info("additionalVolume: creating file-backed volume", "machine", machineScope.Name(), "slot", slotName, "value", volumeValue)
		} else {
			volumeValue = fmt.Sprintf("%s:%d", storageName, vol.SizeGB)
			machineScope.Info("additionalVolume: creating block-backed volume", "machine", machineScope.Name(), "slot", slotName, "value", volumeValue)
		}

		if vol.Discard != nil && *vol.Discard {
			volumeValue = fmt.Sprintf("%s,discard=on", volumeValue)
		}
		if vol.IOThread != nil && *vol.IOThread {
			volumeValue = fmt.Sprintf("%s,iothread=1", volumeValue)
		}
		if vol.SSD != nil && *vol.SSD {
			volumeValue = fmt.Sprintf("%s,ssd=1", volumeValue)
		}

		*vmOptions = append(*vmOptions, proxmox.VirtualMachineOption{Name: vol.Disk, Value: volumeValue})
		pendingInReconcile[slotName] = struct{}{}
		if pendingGuardEnabled {
			markPending(machineScope, slotName)
		}
	}

	return nil
}

func reconcileMachineAddresses(machineScope *scope.MachineScope) error {
	if conditions.GetReason(machineScope.ProxmoxMachine, infrav1.ProxmoxMachineVirtualMachineProvisionedCondition) != infrav1.ProxmoxMachineVirtualMachineProvisionedWaitingForClusterAPIMachineAddressesReason {
		// Machine is in the wrong state to reconcile, we only reconcile powered up VMs
		return nil
	}

	addr, err := getClusterAPIMachineAddresses(machineScope)
	if err != nil {
		machineScope.Error(err, "failed to retrieve machine addresses")
		return err
	}

	machineScope.SetAddresses(addr)

	conditions.Set(machineScope.ProxmoxMachine, metav1.Condition{
		Type:   infrav1.ProxmoxMachineVirtualMachineProvisionedCondition,
		Status: metav1.ConditionFalse,
		Reason: infrav1.ProxmoxMachineVirtualMachineProvisionedWaitingForCloudInitReason,
	})
	return nil
}

func getClusterAPIMachineAddresses(scope *scope.MachineScope) ([]clusterv1.MachineAddress, error) {
	if !scope.VirtualMachine.IsRunning() {
		return nil, errors.New("unable to apply configuration as long as the virtual machine is not running")
	}

	addresses := []clusterv1.MachineAddress{
		{
			Type:    clusterv1.MachineHostName,
			Address: scope.Name(),
		},
	}

	machineAddresses := scope.ProxmoxMachine.GetIPAddresses()
	index := slices.IndexFunc(machineAddresses, func(s infrav1.IPAddressesSpec) bool {
		return s.NetName == "default"
	})
	// TODO: DHCP as InternalIP
	if index == -1 {
		return addresses, errors.Errorf("Machine has no default IPAddresses")
	}

	defaultAddresses := machineAddresses[index]

	for _, address := range slices.Concat(defaultAddresses.IPv4, defaultAddresses.IPv6) {
		if address == "" {
			continue
		}
		addresses = append(addresses, clusterv1.MachineAddress{
			Type:    clusterv1.MachineInternalIP,
			Address: address,
		})
	}

	return addresses, nil
}

func disksSpecHash(disks any) string {
	if disks == nil {
		return ""
	}

	b, err := json.Marshal(disks)
	if err != nil {
		return ""
	}

	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ensureStorageSelection returns the boot and additional storage pools for the
// given machine and node. If a prior selection exists in status and still
// matches the current node and disks spec, it is reused. Otherwise a new
// selection is computed and persisted in status.
func ensureStorageSelection(ctx context.Context, machineScope *scope.MachineScope, nodeName string) (bootStorage, additionalStorage string, err error) {
	if nodeName == "" {
		return "", "", errors.New("node name is required to ensure storage selection")
	}

	pm := machineScope.ProxmoxMachine
	disksHash := disksSpecHash(pm.Spec.Disks)

	if pm.Status.StorageSelection != nil {
		selection := pm.Status.StorageSelection
		if selection.Node == nodeName && selection.DisksHash == disksHash && selection.BootStorage != "" && selection.AdditionalStorage != "" {
			machineScope.Info("using persisted storage selection", "node", nodeName, "bootStorage", selection.BootStorage, "additionalStorage", selection.AdditionalStorage)
			return selection.BootStorage, selection.AdditionalStorage, nil
		}
	}

	bootStorage, additionalStorage, err = selectNodeStorages(ctx, machineScope, nodeName)
	if err != nil {
		return "", "", err
	}

	pm.Status.StorageSelection = &infrav1.StorageSelectionStatus{
		Node:              nodeName,
		BootStorage:       bootStorage,
		AdditionalStorage: additionalStorage,
		DisksHash:         disksHash,
	}

	machineScope.Info("computed and stored storage selection", "node", nodeName, "bootStorage", bootStorage, "additionalStorage", additionalStorage)
	return bootStorage, additionalStorage, nil
}

func reservedAdditionalCapacityByPool(ctx context.Context, machineScope *scope.MachineScope, nodeName string) (map[string]uint64, error) {
	reserved := make(map[string]uint64)
	reservedCount := make(map[string]int)

	if nodeName == "" {
		return reserved, nil
	}

	pmList, err := machineScope.InfraCluster.ListProxmoxMachinesForCluster(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "cannot list ProxmoxMachines for reserved capacity")
	}

	current := machineScope.ProxmoxMachine
	const GiB = uint64(1024 * 1024 * 1024)

	for _, pm := range pmList {
		if pm.Name == current.Name {
			continue
		}
		if pm.Status.ProxmoxNode == nil || *pm.Status.ProxmoxNode != nodeName {
			continue
		}
		if ptr.Deref(pm.Status.Initialization.Provisioned, false) {
			continue
		}
		if pm.Status.StorageSelection == nil || pm.Status.StorageSelection.AdditionalStorage == "" {
			continue
		}

		pool := pm.Status.StorageSelection.AdditionalStorage
		disks := pm.Spec.Disks
		if disks == nil {
			continue
		}

		for _, vol := range disks.AdditionalVolumes {
			if vol.SizeGB <= 0 {
				continue
			}
			if vol.Storage != nil && *vol.Storage != "" {
				continue
			}
			if pm.Spec.Storage != nil && *pm.Spec.Storage != "" {
				continue
			}
			reserved[pool] += uint64(vol.SizeGB) * GiB
			reservedCount[pool]++
		}
	}

	if len(reserved) > 0 {
		machineScope.Logger.WithValues("node", nodeName).Info("reserved additional capacity by pool", "reservedBytes", reserved, "reservedVolumes", reservedCount)
	}

	return reserved, nil
}

func selectNodeStorages(ctx context.Context, machineScope *scope.MachineScope, nodeName string) (bootStorage, additionalStorage string, err error) {
	if nodeName == "" {
		return "", "", errors.New("node name is required to select storages")
	}

	storages, err := machineScope.InfraCluster.ProxmoxClient.ListNodeStorages(ctx, nodeName)
	if err != nil {
		return "", "", errors.Wrapf(err, "cannot list storages for node %s", nodeName)
	}

	var candidates []proxmox.StorageStatus
	for _, s := range storages {
		if !s.Enabled || !s.Active || s.Shared || !strings.Contains(s.Content, "images") {
			continue
		}
		candidates = append(candidates, s)
	}

	if len(candidates) == 0 {
		return "", "", fmt.Errorf("no eligible local image storages found on node %s", nodeName)
	}

	reserved, err := reservedAdditionalCapacityByPool(ctx, machineScope, nodeName)
	if err != nil {
		return "", "", err
	}

	effectiveFree := func(s proxmox.StorageStatus) uint64 {
		base := s.Avail
		if s.VirtualAvail > 0 {
			base = s.VirtualAvail
		}
		if reservedBytes, ok := reserved[s.Name]; ok {
			if reservedBytes >= base {
				return 0
			}
			return base - reservedBytes
		}
		return base
	}

	logger := machineScope.Logger.WithValues("node", nodeName)
	for _, c := range candidates {
		logger.Info("storage candidate",
			"name", c.Name,
			"type", c.Type,
			"enabled", c.Enabled,
			"active", c.Active,
			"shared", c.Shared,
			"content", c.Content,
			"total", c.Total,
			"avail", c.Avail,
			"virtualAllocated", c.VirtualAllocated,
			"virtualAvail", c.VirtualAvail,
			"reservedBytes", reserved[c.Name],
			"effectiveFree", effectiveFree(c),
		)
	}

	const GiB = uint64(1024 * 1024 * 1024)
	var bootSizeBytes uint64
	var largestAdditionalSizeBytes uint64

	if disks := machineScope.ProxmoxMachine.Spec.Disks; disks != nil {
		if disks.BootVolume != nil && disks.BootVolume.SizeGB > 0 {
			bootSizeBytes = uint64(disks.BootVolume.SizeGB) * GiB
		}
		for _, vol := range disks.AdditionalVolumes {
			if vol.SizeGB <= 0 {
				continue
			}
			if vol.Storage != nil && *vol.Storage != "" {
				continue
			}
			if machineScope.ProxmoxMachine.Spec.Storage != nil && *machineScope.ProxmoxMachine.Spec.Storage != "" {
				continue
			}
			sizeBytes := uint64(vol.SizeGB) * GiB
			if sizeBytes > largestAdditionalSizeBytes {
				largestAdditionalSizeBytes = sizeBytes
			}
		}
	}

	bootCandidates := slices.Clone(candidates)
	additionalCandidates := slices.Clone(candidates)

	if bootSizeBytes > 0 {
		bootCandidates = bootCandidates[:0]
		for _, candidate := range candidates {
			if effectiveFree(candidate) >= bootSizeBytes {
				bootCandidates = append(bootCandidates, candidate)
			}
		}
		if len(bootCandidates) == 0 {
			return "", "", fmt.Errorf("no eligible local image storage on node %s has enough free capacity for boot disk", nodeName)
		}
	}

	if largestAdditionalSizeBytes > 0 {
		additionalCandidates = additionalCandidates[:0]
		for _, candidate := range candidates {
			if effectiveFree(candidate) >= largestAdditionalSizeBytes {
				additionalCandidates = append(additionalCandidates, candidate)
			}
		}
		if len(additionalCandidates) == 0 {
			return "", "", fmt.Errorf("no eligible local image storage on node %s has enough free capacity for additional volumes", nodeName)
		}
	}

	sort.SliceStable(bootCandidates, func(i, j int) bool {
		return effectiveFree(bootCandidates[i]) > effectiveFree(bootCandidates[j])
	})
	sort.SliceStable(additionalCandidates, func(i, j int) bool {
		return effectiveFree(additionalCandidates[i]) > effectiveFree(additionalCandidates[j])
	})

	bootStorage = bootCandidates[0].Name
	additionalStorage = additionalCandidates[0].Name

	logger.Info("selected node storages", "bootStorage", bootStorage, "additionalStorage", additionalStorage)
	return bootStorage, additionalStorage, nil
}

func createVM(ctx context.Context, scope *scope.MachineScope) (proxmox.VMCloneResponse, error) {
	vmid, err := getVMID(ctx, scope)
	if err != nil {
		if errors.Is(err, ErrNoVMIDInRangeFree) {
			conditions.Set(scope.ProxmoxMachine, metav1.Condition{
				Type:    infrav1.ProxmoxMachineVirtualMachineProvisionedCondition,
				Status:  metav1.ConditionFalse,
				Reason:  infrav1.ProxmoxMachineVirtualMachineProvisionedVMProvisionFailedReason,
				Message: err.Error(),
			})
		}
		return proxmox.VMCloneResponse{}, err
	}

	options := proxmox.VMCloneRequest{
		Node:  scope.ProxmoxMachine.GetSourceNode(),
		NewID: int(vmid),
		Name:  scope.ProxmoxMachine.GetName(),
	}

	if scope.ProxmoxMachine.Spec.Description != nil {
		options.Description = *scope.ProxmoxMachine.Spec.Description
	}
	if scope.ProxmoxMachine.Spec.Format != nil {
		options.Format = string(*scope.ProxmoxMachine.Spec.Format)
	}
	var full uint8
	if ptr.Deref(scope.ProxmoxMachine.Spec.Full, true) {
		full = 1
	}
	options.Full = full
	if scope.ProxmoxMachine.Spec.Pool != nil {
		options.Pool = *scope.ProxmoxMachine.Spec.Pool
	}
	if scope.ProxmoxMachine.Spec.SnapName != nil {
		options.SnapName = *scope.ProxmoxMachine.Spec.SnapName
	}
	if scope.ProxmoxMachine.Spec.Storage != nil {
		options.Storage = *scope.ProxmoxMachine.Spec.Storage
	}

	if scope.InfraCluster.ProxmoxCluster.Status.NodeLocations == nil {
		scope.InfraCluster.ProxmoxCluster.Status.NodeLocations = new(infrav1.NodeLocations)
	}

	if scope.ProxmoxMachine.Status.ProxmoxNode != nil && strings.TrimSpace(*scope.ProxmoxMachine.Status.ProxmoxNode) != "" {
		options.Target = strings.TrimSpace(*scope.ProxmoxMachine.Status.ProxmoxNode)
	}

	if options.Target == "" && (len(scope.InfraCluster.ProxmoxCluster.Spec.AllowedNodes) > 0 || len(scope.ProxmoxMachine.Spec.AllowedNodes) > 0) {
		var err error
		options.Target, err = selectNextNode(ctx, scope)
		if err != nil {
			if errors.As(err, &scheduler.InsufficientMemoryError{}) {
				conditions.Set(scope.ProxmoxMachine, metav1.Condition{
					Type:    infrav1.ProxmoxMachineVirtualMachineProvisionedCondition,
					Status:  metav1.ConditionFalse,
					Reason:  infrav1.ProxmoxMachineVirtualMachineProvisionedVMProvisionFailedReason,
					Message: err.Error(),
				})
			}
			return proxmox.VMCloneResponse{}, err
		}
	}

	templateID := scope.ProxmoxMachine.GetTemplateID()
	if templateID == -1 {
		var err error
		templateSelectorTags := scope.ProxmoxMachine.GetTemplateSelectorTags()
		templateMatchPolicy := string(scope.ProxmoxMachine.GetTemplateMatchPolicy())
		options.Node, templateID, err = scope.InfraCluster.ProxmoxClient.FindVMTemplateByTags(ctx, templateSelectorTags, templateMatchPolicy, options.Target)

		if err != nil {
			if errors.Is(err, goproxmox.ErrTemplateNotFound) {
				conditions.Set(scope.ProxmoxMachine, metav1.Condition{
					Type:    infrav1.ProxmoxMachineVirtualMachineProvisionedCondition,
					Status:  metav1.ConditionFalse,
					Reason:  infrav1.ProxmoxMachineVirtualMachineProvisionedVMProvisionFailedReason,
					Message: err.Error(),
				})
			}
			return proxmox.VMCloneResponse{}, err
		}
	}

	node := options.Target
	if node == "" {
		node = options.Node
	}

	if options.Storage == "" {
		bootStorage, _, err := ensureStorageSelection(ctx, scope, node)
		if err != nil {
			conditions.Set(scope.ProxmoxMachine, metav1.Condition{
				Type:    infrav1.ProxmoxMachineVirtualMachineProvisionedCondition,
				Status:  metav1.ConditionFalse,
				Reason:  infrav1.ProxmoxMachineVirtualMachineProvisionedVMProvisionFailedReason,
				Message: err.Error(),
			})
			return proxmox.VMCloneResponse{}, err
		}
		options.Storage = bootStorage
	}

	res, err := scope.InfraCluster.ProxmoxClient.CloneVM(ctx, int(templateID), options)
	if err != nil {
		return res, err
	}

	scope.ProxmoxMachine.Status.ProxmoxNode = ptr.To(node)

	// if the creation was successful, we store the information about the node in the
	// cluster status
	scope.InfraCluster.ProxmoxCluster.AddNodeLocation(infrav1.NodeLocation{
		Machine: corev1.LocalObjectReference{Name: options.Name},
		Node:    node,
	}, util.IsControlPlaneMachine(scope.Machine))

	return res, scope.InfraCluster.PatchObject()
}

func getVMID(ctx context.Context, scope *scope.MachineScope) (int64, error) {
	if scope.ProxmoxMachine.Spec.VMIDRange != nil {
		vmIDRangeStart := scope.ProxmoxMachine.Spec.VMIDRange.Start
		vmIDRangeEnd := scope.ProxmoxMachine.Spec.VMIDRange.End
		if vmIDRangeStart != 0 && vmIDRangeEnd != 0 {
			return getNextFreeVMIDfromRange(ctx, scope, vmIDRangeStart, vmIDRangeEnd)
		}
	}
	// If VMIDRange is not defined, return 0 to let luthermonson/go-proxmox get the next free id.
	return 0, nil
}

func getNextFreeVMIDfromRange(ctx context.Context, scope *scope.MachineScope, vmIDRangeStart int64, vmIDRangeEnd int64) (int64, error) {
	usedVMIDs, err := getUsedVMIDs(ctx, scope)
	if err != nil {
		return 0, err
	}
	// Get next free vmid from the range
	for i := vmIDRangeStart; i <= vmIDRangeEnd; i++ {
		if slices.Contains(usedVMIDs, i) {
			continue
		}
		if vmidFree, err := scope.InfraCluster.ProxmoxClient.CheckID(ctx, i); err == nil && vmidFree {
			return i, nil
		} else if err != nil {
			return 0, err
		}
	}
	// Fail if we can't find a free vmid in the range.
	return 0, ErrNoVMIDInRangeFree
}

func getUsedVMIDs(ctx context.Context, scope *scope.MachineScope) ([]int64, error) {
	// Get all used vmids from existing ProxmoxMachines
	usedVMIDs := []int64{}
	proxmoxMachines, err := scope.InfraCluster.ListProxmoxMachinesForCluster(ctx)
	if err != nil {
		return usedVMIDs, err
	}
	for _, proxmoxMachine := range proxmoxMachines {
		if proxmoxMachine.GetVirtualMachineID() != -1 {
			usedVMIDs = append(usedVMIDs, proxmoxMachine.GetVirtualMachineID())
		}
	}
	return usedVMIDs, nil
}

var selectNextNode = scheduler.ScheduleVM

func unmountCloudInitISO(ctx context.Context, machineScope *scope.MachineScope) error {
	return machineScope.InfraCluster.ProxmoxClient.UnmountCloudInitISO(ctx, machineScope.VirtualMachine, inject.CloudInitISODevice)
}
