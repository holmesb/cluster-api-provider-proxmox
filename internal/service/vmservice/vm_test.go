/*
Copyright 2023-2025 IONOS Cloud.

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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	capierrors "sigs.k8s.io/cluster-api/errors" //nolint:staticcheck

	infrav1alpha1 "github.com/ionos-cloud/cluster-api-provider-proxmox/api/v1alpha1"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/internal/service/scheduler"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox/goproxmox"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/scope"
)

func init() {
	EnablePendingGuard(false)
}

func TestReconcileVM_EverythingReady(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	vm := newRunningVM()
	machineScope.SetVirtualMachineID(int64(vm.VMID))
	machineScope.ProxmoxMachine.Spec.SourceNode = "node1"
	machineScope.ProxmoxMachine.Status.IPAddresses = map[string]infrav1alpha1.IPAddress{infrav1alpha1.DefaultNetworkDevice: {IPV4: "10.10.10.10"}}
	machineScope.ProxmoxMachine.Status.BootstrapDataProvided = ptr.To(true)
	machineScope.ProxmoxMachine.Status.Ready = true

	proxmoxClient.EXPECT().GetVM(context.Background(), "node1", int64(123)).Return(vm, nil).Once()
	proxmoxClient.EXPECT().CloudInitStatus(context.Background(), vm).Return(false, nil).Once()
	proxmoxClient.EXPECT().QemuAgentStatus(context.Background(), vm).Return(nil).Once()

	result, err := ReconcileVM(context.Background(), machineScope)
	require.NoError(t, err)
	require.Equal(t, infrav1alpha1.VirtualMachineStateReady, result.State)
	require.Equal(t, "10.10.10.10", machineScope.ProxmoxMachine.Status.Addresses[1].Address)
}

func TestReconcileVM_QemuAgentCheckDisabled(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	vm := newRunningVM()
	machineScope.SetVirtualMachineID(int64(vm.VMID))
	machineScope.ProxmoxMachine.Status.IPAddresses = map[string]infrav1alpha1.IPAddress{infrav1alpha1.DefaultNetworkDevice: {IPV4: "10.10.10.10"}}
	machineScope.ProxmoxMachine.Status.BootstrapDataProvided = ptr.To(true)
	machineScope.ProxmoxMachine.Status.Ready = true

	machineScope.ProxmoxMachine.Spec.SourceNode = "node1"
	machineScope.ProxmoxMachine.Spec.Checks = &infrav1alpha1.ProxmoxMachineChecks{
		SkipQemuGuestAgent: ptr.To(true),
	}

	proxmoxClient.EXPECT().GetVM(context.Background(), "node1", int64(123)).Return(vm, nil).Once()
	// proxmoxClient.EXPECT().CloudInitStatus(context.Background(), vm).Return(false, nil).Once()

	result, err := ReconcileVM(context.Background(), machineScope)
	require.NoError(t, err)
	require.Equal(t, infrav1alpha1.VirtualMachineStateReady, result.State)
	require.Equal(t, "10.10.10.10", machineScope.ProxmoxMachine.Status.Addresses[1].Address)
}

func TestReconcileVM_CloudInitCheckDisabled(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	vm := newRunningVM()
	machineScope.SetVirtualMachineID(int64(vm.VMID))
	machineScope.ProxmoxMachine.Status.IPAddresses = map[string]infrav1alpha1.IPAddress{infrav1alpha1.DefaultNetworkDevice: {IPV4: "10.10.10.10"}}
	machineScope.ProxmoxMachine.Status.BootstrapDataProvided = ptr.To(true)
	machineScope.ProxmoxMachine.Status.Ready = true
	machineScope.ProxmoxMachine.Spec.SourceNode = "node1"
	machineScope.ProxmoxMachine.Spec.Checks = &infrav1alpha1.ProxmoxMachineChecks{
		SkipCloudInitStatus: ptr.To(true),
	}

	proxmoxClient.EXPECT().GetVM(context.Background(), "node1", int64(123)).Return(vm, nil).Once()
	proxmoxClient.EXPECT().QemuAgentStatus(context.Background(), vm).Return(nil)

	result, err := ReconcileVM(context.Background(), machineScope)
	require.NoError(t, err)
	require.Equal(t, infrav1alpha1.VirtualMachineStateReady, result.State)
	require.Equal(t, "10.10.10.10", machineScope.ProxmoxMachine.Status.Addresses[1].Address)
}

func TestReconcileVM_InitCheckDisabled(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	vm := newRunningVM()
	machineScope.SetVirtualMachineID(int64(vm.VMID))
	machineScope.ProxmoxMachine.Status.IPAddresses = map[string]infrav1alpha1.IPAddress{infrav1alpha1.DefaultNetworkDevice: {IPV4: "10.10.10.10"}}
	machineScope.ProxmoxMachine.Status.BootstrapDataProvided = ptr.To(true)
	machineScope.ProxmoxMachine.Status.Ready = true
	machineScope.ProxmoxMachine.Spec.SourceNode = "node1"
	machineScope.ProxmoxMachine.Spec.Checks = &infrav1alpha1.ProxmoxMachineChecks{
		SkipCloudInitStatus: ptr.To(true),
		SkipQemuGuestAgent:  ptr.To(true),
	}

	proxmoxClient.EXPECT().GetVM(context.Background(), "node1", int64(123)).Return(vm, nil).Once()

	result, err := ReconcileVM(context.Background(), machineScope)
	require.NoError(t, err)
	require.Equal(t, infrav1alpha1.VirtualMachineStateReady, result.State)
	require.Equal(t, "10.10.10.10", machineScope.ProxmoxMachine.Status.Addresses[1].Address)
}
func TestEnsureVirtualMachine_CreateVM_FullOptions(t *testing.T) {
	ctx := context.Background()
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.ProxmoxMachine.Spec.Description = ptr.To("test vm")
	machineScope.ProxmoxMachine.Spec.Format = ptr.To(infrav1alpha1.TargetFileStorageFormatRaw)
	machineScope.ProxmoxMachine.Spec.Full = ptr.To(true)
	machineScope.ProxmoxMachine.Spec.Pool = ptr.To("pool")
	machineScope.ProxmoxMachine.Spec.SnapName = ptr.To("snap")
	machineScope.ProxmoxMachine.Spec.Storage = ptr.To("storage")
	machineScope.ProxmoxMachine.Spec.AllowedNodes = []string{"node2"}
	machineScope.ProxmoxMachine.Spec.TemplateID = ptr.To(int32(123))
	machineScope.ProxmoxMachine.Spec.SourceNode = "node1"
	expectedOptions := proxmox.VMCloneRequest{
		Node:        "node1",
		Name:        "test",
		Description: "test vm",
		Format:      "raw",
		Full:        1,
		Pool:        "pool",
		SnapName:    "snap",
		Storage:     "storage",
		Target:      "node2",
	}

	response := proxmox.VMCloneResponse{
		NewID: 123,
		Task:  newTask(),
	}
	proxmoxClient.EXPECT().
		GetReservableMemoryBytes(ctx, "node2", uint64(100)).
		Return(uint64(5000), nil).
		Once()

	proxmoxClient.EXPECT().CloneVM(ctx, 123, expectedOptions).Return(response, nil).Once()

	requeue, err := ensureVirtualMachine(ctx, machineScope)
	require.NoError(t, err)
	require.True(t, requeue)

	require.Equal(t, "node2", *machineScope.ProxmoxMachine.Status.ProxmoxNode)
	require.True(t, machineScope.InfraCluster.ProxmoxCluster.HasMachine(machineScope.Name(), false))
	requireConditionIsFalse(t, machineScope.ProxmoxMachine, infrav1alpha1.VMProvisionedCondition)
}

func TestEnsureVirtualMachine_CreateVM_FullOptions_TemplateSelector_SharedStorage(t *testing.T) {
	ctx := context.Background()
	vmTemplateTags := []string{"foo", "bar"}
	allowedNodes := []string{"node1", "node2"}

	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.ProxmoxMachine.Spec.VirtualMachineCloneSpec = infrav1alpha1.VirtualMachineCloneSpec{
		TemplateSource: infrav1alpha1.TemplateSource{
			LocalStorage: ptr.To(true),
			TemplateSelector: &infrav1alpha1.TemplateSelector{
				MatchTags: vmTemplateTags,
			},
		},
	}
	machineScope.ProxmoxMachine.Spec.LocalStorage = ptr.To(false)
	machineScope.ProxmoxMachine.Spec.Description = ptr.To("test vm")
	machineScope.ProxmoxMachine.Spec.Format = ptr.To(infrav1alpha1.TargetFileStorageFormatRaw)
	machineScope.ProxmoxMachine.Spec.Full = ptr.To(true)
	machineScope.ProxmoxMachine.Spec.Pool = ptr.To("pool")
	machineScope.ProxmoxMachine.Spec.SnapName = ptr.To("snap")
	machineScope.ProxmoxMachine.Spec.Storage = ptr.To("storage")
	machineScope.ProxmoxMachine.Spec.AllowedNodes = allowedNodes
	expectedOptions := proxmox.VMCloneRequest{
		Node:        "node1",
		Name:        "test",
		Description: "test vm",
		Format:      "raw",
		Full:        1,
		Pool:        "pool",
		SnapName:    "snap",
		Storage:     "storage",
		Target:      "node1",
	}

	proxmoxClient.EXPECT().
		GetReservableMemoryBytes(ctx, "node1", uint64(100)).
		Return(uint64(5000), nil).
		Once()

	proxmoxClient.EXPECT().
		GetReservableMemoryBytes(ctx, "node2", uint64(100)).
		Return(uint64(5000), nil).
		Once()

	proxmoxClient.EXPECT().
		FindVMTemplatesByTags(ctx, vmTemplateTags, allowedNodes, false).
		Return(map[string]int32{"node1": int32(123), "node2": int32(124)}, nil).
		Once()

	response := proxmox.VMCloneResponse{NewID: 123, Task: newTask()}
	proxmoxClient.EXPECT().
		CloneVM(ctx, 123, expectedOptions).
		Return(response, nil).
		Once()

	requeue, err := ensureVirtualMachine(ctx, machineScope)
	require.NoError(t, err)
	require.True(t, requeue)

	require.Equal(t, "node1", *machineScope.ProxmoxMachine.Status.ProxmoxNode)
	require.True(t, machineScope.InfraCluster.ProxmoxCluster.HasMachine(machineScope.Name(), false))
	requireConditionIsFalse(t, machineScope.ProxmoxMachine, infrav1alpha1.VMProvisionedCondition)
}

func TestEnsureVirtualMachine_CreateVM_FullOptions_TemplateSelector_LocalStorage(t *testing.T) {
	ctx := context.Background()
	vmTemplateTags := []string{"foo", "bar"}
	allowedNodes := []string{"node1", "node2"}

	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.ProxmoxMachine.Spec.VirtualMachineCloneSpec = infrav1alpha1.VirtualMachineCloneSpec{
		TemplateSource: infrav1alpha1.TemplateSource{
			LocalStorage: ptr.To(false),
			TemplateSelector: &infrav1alpha1.TemplateSelector{
				MatchTags: vmTemplateTags,
			},
		},
	}
	machineScope.ProxmoxMachine.Spec.Description = ptr.To("test vm")
	machineScope.ProxmoxMachine.Spec.Format = ptr.To(infrav1alpha1.TargetFileStorageFormatRaw)
	machineScope.ProxmoxMachine.Spec.Full = ptr.To(true)
	machineScope.ProxmoxMachine.Spec.Pool = ptr.To("pool")
	machineScope.ProxmoxMachine.Spec.SnapName = ptr.To("snap")
	machineScope.ProxmoxMachine.Spec.Storage = ptr.To("storage")
	machineScope.ProxmoxMachine.Spec.LocalStorage = ptr.To(true)
	machineScope.ProxmoxMachine.Spec.AllowedNodes = allowedNodes
	expectedOptions := proxmox.VMCloneRequest{
		Node:        "node1",
		Name:        "test",
		Description: "test vm",
		Format:      "raw",
		Full:        1,
		Pool:        "pool",
		SnapName:    "snap",
		Storage:     "storage",
		Target:      "node1",
	}

	proxmoxClient.EXPECT().
		GetReservableMemoryBytes(ctx, "node1", uint64(100)).
		Return(uint64(5000), nil).
		Once()

	proxmoxClient.EXPECT().
		GetReservableMemoryBytes(ctx, "node2", uint64(100)).
		Return(uint64(5000), nil).
		Once()

	proxmoxClient.EXPECT().
		FindVMTemplatesByTags(ctx, vmTemplateTags, allowedNodes, true).
		Return(map[string]int32{"node1": int32(123), "node2": int32(124)}, nil).
		Once()

	response := proxmox.VMCloneResponse{NewID: 123, Task: newTask()}
	proxmoxClient.EXPECT().
		CloneVM(ctx, 123, expectedOptions).
		Return(response, nil).
		Once()

	requeue, err := ensureVirtualMachine(ctx, machineScope)
	require.NoError(t, err)
	require.True(t, requeue)

	require.Equal(t, "node1", *machineScope.ProxmoxMachine.Status.ProxmoxNode)
	require.True(t, machineScope.InfraCluster.ProxmoxCluster.HasMachine(machineScope.Name(), false))
	requireConditionIsFalse(t, machineScope.ProxmoxMachine, infrav1alpha1.VMProvisionedCondition)
}

func TestEnsureVirtualMachine_CreateVM_FullOptions_TemplateSelector_VMTemplateNotFound(t *testing.T) {
	ctx := context.Background()
	vmTemplateTags := []string{"foo", "bar"}
	localStorage := true
	allowedNodes := []string{"node1", "node2"}

	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.ProxmoxMachine.Spec.VirtualMachineCloneSpec = infrav1alpha1.VirtualMachineCloneSpec{
		TemplateSource: infrav1alpha1.TemplateSource{
			TemplateSelector: &infrav1alpha1.TemplateSelector{
				MatchTags: vmTemplateTags,
			},
		},
	}
	machineScope.ProxmoxMachine.Spec.LocalStorage = ptr.To(true)
	machineScope.ProxmoxMachine.Spec.Description = ptr.To("test vm")
	machineScope.ProxmoxMachine.Spec.Format = ptr.To(infrav1alpha1.TargetFileStorageFormatRaw)
	machineScope.ProxmoxMachine.Spec.Full = ptr.To(true)
	machineScope.ProxmoxMachine.Spec.Pool = ptr.To("pool")
	machineScope.ProxmoxMachine.Spec.SnapName = ptr.To("snap")
	machineScope.ProxmoxMachine.Spec.Storage = ptr.To("storage")
	machineScope.ProxmoxMachine.Spec.AllowedNodes = allowedNodes

	proxmoxClient.EXPECT().FindVMTemplatesByTags(context.Background(), vmTemplateTags, allowedNodes, localStorage).Return(map[string]int32{}, goproxmox.ErrTemplateNotFound).Once()

	_, err := createVM(ctx, machineScope)

	require.Equal(t, ptr.To(capierrors.MachineStatusError("VMTemplateNotFound")), machineScope.ProxmoxMachine.Status.FailureReason)
	require.Equal(t, ptr.To("VM template not found"), machineScope.ProxmoxMachine.Status.FailureMessage)
	require.Error(t, err)
	require.Contains(t, "VM template not found", err.Error())
}

// localstorage false.
func TestEnsureVirtualMachine_CreateVM_SelectNode(t *testing.T) {
	vmTemplateTags := []string{"foo", "bar"}
	localStorage := false
	allowedNodes := []string{"node3"}

	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.ProxmoxMachine.Spec.VirtualMachineCloneSpec = infrav1alpha1.VirtualMachineCloneSpec{
		TemplateSource: infrav1alpha1.TemplateSource{
			TemplateSelector: &infrav1alpha1.TemplateSelector{
				MatchTags: vmTemplateTags,
			},
		},
	}
	machineScope.ProxmoxMachine.Spec.AllowedNodes = allowedNodes
	machineScope.ProxmoxMachine.Spec.LocalStorage = ptr.To(localStorage)
	storage := "local-lvm"
	machineScope.ProxmoxMachine.Spec.Storage = &storage

	proxmoxClient.EXPECT().
		FindVMTemplatesByTags(context.Background(), vmTemplateTags, allowedNodes, localStorage).
		Return(map[string]int32{"node1": 123}, nil).
		Once()

	selectNextNode = func(context.Context, *scope.MachineScope, map[string]int32, []string) (string, int32, error) {
		return "node3", 0, nil
	}
	t.Cleanup(func() { selectNextNode = scheduler.ScheduleVM })

	expectedOptions := proxmox.VMCloneRequest{
		Node:    "node1",
		Name:    "test",
		Target:  "node3",
		Storage: "local-lvm",
	}

	response := proxmox.VMCloneResponse{
		NewID: 123,
		Task:  newTask(),
	}
	proxmoxClient.EXPECT().
		CloneVM(context.Background(), 123, expectedOptions).
		Return(response, nil).
		Once()

	requeue, err := ensureVirtualMachine(context.Background(), machineScope)
	require.NoError(t, err)
	require.True(t, requeue)

	require.Equal(t, "node3", *machineScope.ProxmoxMachine.Status.ProxmoxNode)
	require.True(t, machineScope.InfraCluster.ProxmoxCluster.HasMachine(machineScope.Name(), false))
	requireConditionIsFalse(t, machineScope.ProxmoxMachine, infrav1alpha1.VMProvisionedCondition)
}

func TestEnsureVirtualMachine_CreateVM_SelectNode_MachineAllowedNodes_SharedStorage(t *testing.T) {
	clusterAllowedNodes := []string{"node1", "node2", "node3", "node4"}
	proxmoxMachineAllowedNodes := []string{"node1", "node2"}

	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.InfraCluster.ProxmoxCluster.Spec.AllowedNodes = clusterAllowedNodes
	machineScope.ProxmoxMachine.Spec.AllowedNodes = proxmoxMachineAllowedNodes

	// we need to search for templates, as we cannot do node scheduling without them
	vmTemplateTags := []string{"foo", "bar"}
	machineScope.ProxmoxMachine.Spec.LocalStorage = ptr.To(false)
	machineScope.ProxmoxMachine.Spec.VirtualMachineCloneSpec = infrav1alpha1.VirtualMachineCloneSpec{
		TemplateSource: infrav1alpha1.TemplateSource{
			LocalStorage: ptr.To(false),
			TemplateSelector: &infrav1alpha1.TemplateSelector{
				MatchTags: vmTemplateTags,
			},
		},
	}
	templateMap := map[string]int32{"node1": int32(122)}

	proxmoxClient.EXPECT().
		FindVMTemplatesByTags(context.Background(), vmTemplateTags, proxmoxMachineAllowedNodes, false).
		Return(templateMap, nil).
		Once()

	// Force the scheduler to pick node2 as the target node.
	selectNextNode = func(context.Context, *scope.MachineScope, map[string]int32, []string) (string, int32, error) {
		return "node2", 123, nil
	}
	defer func() { selectNextNode = scheduler.ScheduleVM }()

	// With no storage specified on the machine or volume, createVM will query
	// storages on the chosen node and pick appropriate pools.
	proxmoxClient.EXPECT().
		ListNodeStorages(context.Background(), "node2").
		Return([]proxmox.StorageStatus{
			{
				Name:         "local-node2-a",
				Enabled:      true,
				Active:       true,
				Shared:       false,
				Content:      "images,rootdir",
				Avail:        20,
				VirtualAvail: 20,
			},
			{
				Name:         "local-node2-b",
				Enabled:      true,
				Active:       true,
				Shared:       false,
				Content:      "images",
				Avail:        10,
				VirtualAvail: 10,
			},
		}, nil).
		Once()

	// selectNodeStorages will sort by VirtualAvail descending and, for the boot
	// volume (clone storage), use the second candidate when more than one is
	// available. That means we expect Storage to be "local-node2-b" here.
	expectedOptions := proxmox.VMCloneRequest{
		Node:    "node1",
		Name:    "test",
		Target:  "node2",
		Storage: "local-node2-a",
	}

	response := proxmox.VMCloneResponse{NewID: 122, Task: newTask()}
	proxmoxClient.EXPECT().CloneVM(context.Background(), 122, expectedOptions).Return(response, nil).Once()

	requeue, err := ensureVirtualMachine(context.Background(), machineScope)
	require.NoError(t, err)
	require.True(t, requeue)

	require.Contains(t, []string{"node2", "node1"}, *machineScope.ProxmoxMachine.Status.ProxmoxNode)
	require.True(t, machineScope.InfraCluster.ProxmoxCluster.HasMachine(machineScope.Name(), false))
	requireConditionIsFalse(t, machineScope.ProxmoxMachine, infrav1alpha1.VMProvisionedCondition)
}

func TestEnsureVirtualMachine_CreateVM_SelectNode_MachineAllowedNodes_LocalStorage(t *testing.T) {
	clusterAllowedNodes := []string{"node1", "node2", "node3", "node4"}
	proxmoxMachineAllowedNodes := []string{"node1", "node2"}
	vmTemplateTags := []string{"foo", "bar"}

	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.InfraCluster.ProxmoxCluster.Spec.AllowedNodes = clusterAllowedNodes
	machineScope.ProxmoxMachine.Spec.AllowedNodes = proxmoxMachineAllowedNodes
	machineScope.ProxmoxMachine.Spec.LocalStorage = ptr.To(true)

	machineScope.ProxmoxMachine.Spec.VirtualMachineCloneSpec = infrav1alpha1.VirtualMachineCloneSpec{
		TemplateSource: infrav1alpha1.TemplateSource{
			LocalStorage: ptr.To(true),
			TemplateSelector: &infrav1alpha1.TemplateSelector{
				MatchTags: vmTemplateTags,
			},
		},
	}

	proxmoxClient.EXPECT().
		FindVMTemplatesByTags(context.Background(), vmTemplateTags, proxmoxMachineAllowedNodes, true).
		Return(map[string]int32{"node1": int32(122), "node2": int32(123)}, nil).
		Once()

	selectNextNode = func(context.Context, *scope.MachineScope, map[string]int32, []string) (string, int32, error) {
		return "node2", 123, nil
	}
	defer func() { selectNextNode = scheduler.ScheduleVM }()

	// With no explicit storage configured, createVM will query storages on the
	// chosen node (node2) and pick an appropriate local pool.
	proxmoxClient.EXPECT().
		ListNodeStorages(context.Background(), "node2").
		Return([]proxmox.StorageStatus{
			{
				Name:         "local-node2",
				Enabled:      true,
				Active:       true,
				Shared:       false,
				Content:      "images,rootdir",
				Avail:        10,
				VirtualAvail: 10,
			},
		}, nil).
		Once()

	expectedOptions := proxmox.VMCloneRequest{
		Node:    "node2",
		Name:    "test",
		Target:  "node2",
		Storage: "local-node2",
	}

	response := proxmox.VMCloneResponse{NewID: 123, Task: newTask()}
	proxmoxClient.EXPECT().CloneVM(context.Background(), 123, expectedOptions).Return(response, nil).Once()

	requeue, err := ensureVirtualMachine(context.Background(), machineScope)
	require.NoError(t, err)
	require.True(t, requeue)

	require.Equal(t, "node2", *machineScope.ProxmoxMachine.Status.ProxmoxNode)
	require.True(t, machineScope.InfraCluster.ProxmoxCluster.HasMachine(machineScope.Name(), false))
	requireConditionIsFalse(t, machineScope.ProxmoxMachine, infrav1alpha1.VMProvisionedCondition)
}

func TestEnsureVirtualMachine_CreateVM_SelectNode_InsufficientMemory(t *testing.T) {
	allowedNodes := []string{"node1"}
	vmTemplateTags := []string{"foo"}
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.InfraCluster.ProxmoxCluster.Spec.AllowedNodes = allowedNodes
	machineScope.ProxmoxMachine.Spec.VirtualMachineCloneSpec = infrav1alpha1.VirtualMachineCloneSpec{
		TemplateSource: infrav1alpha1.TemplateSource{
			TemplateSelector: &infrav1alpha1.TemplateSelector{
				MatchTags: vmTemplateTags,
			},
		},
	}
	proxmoxClient.EXPECT().
		FindVMTemplatesByTags(context.Background(), vmTemplateTags, allowedNodes, false).
		Return(map[string]int32{"node1": int32(122)}, nil).
		Once()

	selectNextNode = func(context.Context, *scope.MachineScope, map[string]int32, []string) (string, int32, error) {
		return "", 0, fmt.Errorf("error: %w", scheduler.InsufficientMemoryError{})
	}
	t.Cleanup(func() { selectNextNode = scheduler.ScheduleVM })

	_, err := ensureVirtualMachine(context.Background(), machineScope)
	require.Error(t, err)

	require.False(t, machineScope.InfraCluster.ProxmoxCluster.HasMachine(machineScope.Name(), false))
	requireConditionIsFalse(t, machineScope.ProxmoxMachine, infrav1alpha1.VMProvisionedCondition)
	require.True(t, machineScope.HasFailed())
}

func TestEnsureVirtualMachine_CreateVM_VMIDRange(t *testing.T) {
	vmTemplateTags := []string{"foo"}
	allowedNodes := []string{"node1"}
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.InfraCluster.ProxmoxCluster.Spec.AllowedNodes = allowedNodes
	machineScope.ProxmoxMachine.Spec.VirtualMachineCloneSpec = infrav1alpha1.VirtualMachineCloneSpec{
		TemplateSource: infrav1alpha1.TemplateSource{
			TemplateSelector: &infrav1alpha1.TemplateSelector{
				MatchTags: vmTemplateTags,
			},
		},
	}
	machineScope.ProxmoxMachine.Spec.VMIDRange = &infrav1alpha1.VMIDRange{
		Start: 1000,
		End:   1002,
	}

	// Explicit storage keeps this test focused on VMID selection rather than
	// storage auto-selection; createVM will not call ListNodeStorages when
	// Storage is set on the machine spec.
	storage := "local-lvm"
	machineScope.ProxmoxMachine.Spec.Storage = &storage

	proxmoxClient.EXPECT().
		FindVMTemplatesByTags(context.Background(), vmTemplateTags, allowedNodes, false).
		Return(map[string]int32{"node1": int32(123)}, nil).
		Once()

	proxmoxClient.EXPECT().
		GetReservableMemoryBytes(context.Background(), "node1", uint64(100)).
		Return(uint64(5000), nil).
		Once()

	// First ID in range (1000) is reported as unavailable, second (1001) is free.
	proxmoxClient.Mock.On("CheckID", context.Background(), int64(1000)).Return(false, nil)
	proxmoxClient.Mock.On("CheckID", context.Background(), int64(1001)).Return(true, nil)

	expectedOptions := proxmox.VMCloneRequest{
		Node:    "node1",
		NewID:   1001,
		Name:    "test",
		Target:  "node1",
		Storage: "local-lvm",
	}

	response := proxmox.VMCloneResponse{Task: newTask(), NewID: int64(1001)}
	proxmoxClient.EXPECT().CloneVM(context.Background(), 123, expectedOptions).Return(response, nil).Once()

	requeue, err := ensureVirtualMachine(context.Background(), machineScope)
	require.NoError(t, err)
	require.True(t, requeue)

	require.Equal(t, int64(1001), machineScope.ProxmoxMachine.GetVirtualMachineID())
	require.True(t, machineScope.InfraCluster.ProxmoxCluster.HasMachine(machineScope.Name(), false))
	requireConditionIsFalse(t, machineScope.ProxmoxMachine, infrav1alpha1.VMProvisionedCondition)
}

func TestEnsureVirtualMachine_CreateVM_VMIDRangeExhausted(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.ProxmoxMachine.Spec.VMIDRange = &infrav1alpha1.VMIDRange{
		Start: 1000,
		End:   1002,
	}

	proxmoxClient.Mock.On("CheckID", context.Background(), int64(1000)).Return(false, nil)
	proxmoxClient.Mock.On("CheckID", context.Background(), int64(1001)).Return(false, nil)
	proxmoxClient.Mock.On("CheckID", context.Background(), int64(1002)).Return(false, nil)

	requeue, err := ensureVirtualMachine(context.Background(), machineScope)
	require.Error(t, err, ErrNoVMIDInRangeFree)
	require.False(t, requeue)
	require.Equal(t, int64(-1), machineScope.ProxmoxMachine.GetVirtualMachineID())
}

func TestEnsureVirtualMachine_CreateVM_VMIDRangeCheckExisting(t *testing.T) {
	machineScope, proxmoxClient, kubeClient := setupReconcilerTest(t)
	machineScope.ProxmoxMachine.Spec.VMIDRange = &infrav1alpha1.VMIDRange{
		Start: 1000,
		End:   1002,
	}
	machineScope.ProxmoxMachine.Spec.AllowedNodes = []string{"node1"}

	// Add a VM with ID 1000.
	// Make sure the check for a free vmid skips 1000 by ensuring the Proxmox CheckID function isn't called more than once.
	// It is called once when reconciling this test vm.
	vm := newRunningVM()
	vm.Name = "vm1000"
	proxmoxClient.EXPECT().GetVM(context.Background(), "", int64(1000)).Return(vm, nil).Once()
	proxmoxClient.Mock.On("CheckID", context.Background(), int64(1000)).Return(false, nil).Once()
	infraMachine := infrav1alpha1.ProxmoxMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name: "vm1000",
		},
		Spec: infrav1alpha1.ProxmoxMachineSpec{
			VirtualMachineID: ptr.To(int64(1000)),
		},
	}
	machineScope.ProxmoxMachine.Spec.VirtualMachineCloneSpec =
		infrav1alpha1.VirtualMachineCloneSpec{
			TemplateSource: infrav1alpha1.TemplateSource{
				TemplateSelector: &infrav1alpha1.TemplateSelector{
					MatchTags: []string{"foo"},
				},
			},
		}
	machine := clusterv1.Machine{
		ObjectMeta: metav1.ObjectMeta{
			Name: "vm1000",
		},
		Spec: clusterv1.MachineSpec{
			InfrastructureRef: corev1.ObjectReference{
				Kind: "ProxmoxMachine",
				Name: "vm1000",
			},
		},
	}
	machineScopeVMThousand, err := scope.NewMachineScope(scope.MachineScopeParams{
		Client:         kubeClient,
		Logger:         machineScope.Logger,
		Cluster:        machineScope.Cluster,
		Machine:        &machine,
		InfraCluster:   machineScope.InfraCluster,
		ProxmoxMachine: &infraMachine,
		IPAMHelper:     machineScope.IPAMHelper,
	})
	require.NoError(t, err)
	machineScopeVMThousand.SetVirtualMachineID(1000)
	_, err = ensureVirtualMachine(context.Background(), machineScopeVMThousand)
	require.NoError(t, err)

	proxmoxClient.EXPECT().
		FindVMTemplatesByTags(context.Background(), []string{"foo"}, []string{"node1"}, false).
		Return(map[string]int32{"node1": int32(123)}, nil).
		Once()

	proxmoxClient.EXPECT().
		GetReservableMemoryBytes(context.Background(), "node1", uint64(100)).
		Return(uint64(5000), nil).
		Once()

	// Explicit storage keeps this test focused on VMID-range checking and reuse
	// logic, rather than storage auto-selection.
	storage := "local-lvm"
	machineScope.ProxmoxMachine.Spec.Storage = &storage

	proxmoxClient.Mock.On("CheckID", context.Background(), int64(1001)).Return(false, nil).Once()
	proxmoxClient.Mock.On("CheckID", context.Background(), int64(1002)).Return(true, nil).Once()

	expectedOptions := proxmox.VMCloneRequest{
		Node:    "node1",
		NewID:   1002,
		Name:    "test",
		Target:  "node1",
		Storage: "local-lvm",
	}

	response := proxmox.VMCloneResponse{Task: newTask(), NewID: int64(1002)}
	proxmoxClient.EXPECT().CloneVM(context.Background(), 123, expectedOptions).Return(response, nil).Once()

	requeue, err := ensureVirtualMachine(context.Background(), machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
	require.Equal(t, int64(1002), machineScope.ProxmoxMachine.GetVirtualMachineID())
}

func TestEnsureVirtualMachine_FindVM(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.SetVirtualMachineID(123)
	machineScope.ProxmoxMachine.Spec.VirtualMachineCloneSpec = infrav1alpha1.VirtualMachineCloneSpec{
		TemplateSource: infrav1alpha1.TemplateSource{
			SourceNode: "node1",
			TemplateID: ptr.To[int32](123),
		},
	}

	vm := newStoppedVM()
	vm.VirtualMachineConfig.SMBios1 = "uuid=56603c36-46b9-4608-90ae-c731c15eae64"

	proxmoxClient.EXPECT().GetVM(context.Background(), "node1", int64(123)).Return(vm, nil).Once()

	requeue, err := ensureVirtualMachine(context.Background(), machineScope)
	require.NoError(t, err)
	require.False(t, requeue)

	require.Equal(t, vm, machineScope.VirtualMachine)
	require.Equal(t, "proxmox://56603c36-46b9-4608-90ae-c731c15eae64", machineScope.GetProviderID())
}

func TestEnsureVirtualMachine_UpdateVMLocation_Error(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.SetVirtualMachineID(123)
	machineScope.ProxmoxMachine.Spec.VirtualMachineCloneSpec = infrav1alpha1.VirtualMachineCloneSpec{
		TemplateSource: infrav1alpha1.TemplateSource{
			SourceNode: "node1",
			TemplateID: ptr.To[int32](123),
		},
	}
	proxmoxClient.EXPECT().GetVM(context.Background(), "node1", int64(123)).Return(nil, fmt.Errorf("not found")).Once()
	proxmoxClient.EXPECT().FindVMResource(context.Background(), uint64(123)).Return(nil, fmt.Errorf("unavailalbe")).Once()

	_, err := ensureVirtualMachine(context.Background(), machineScope)
	require.Error(t, err)
}

func TestReconcileVirtualMachineConfig_NoConfig(t *testing.T) {
	machineScope, _, _ := setupReconcilerTest(t)
	vm := newStoppedVM()
	vm.VirtualMachineConfig.Description = machineScope.ProxmoxMachine.GetName()
	machineScope.SetVirtualMachine(vm)

	requeue, err := reconcileVirtualMachineConfig(context.Background(), machineScope)
	require.NoError(t, err)
	require.False(t, requeue)
}

func TestReconcileVirtualMachineConfig_ApplyConfig(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.ProxmoxMachine.Spec.Description = ptr.To("test vm")
	machineScope.ProxmoxMachine.Spec.NumSockets = 4
	machineScope.ProxmoxMachine.Spec.NumCores = 4
	machineScope.ProxmoxMachine.Spec.MemoryMiB = 16 * 1024
	machineScope.ProxmoxMachine.Spec.Network = &infrav1alpha1.NetworkSpec{
		Default: &infrav1alpha1.NetworkDevice{Bridge: "vmbr0", Model: ptr.To("virtio"), MTU: ptr.To(uint16(1500))},
		AdditionalDevices: []infrav1alpha1.AdditionalNetworkDevice{
			{
				Name:          "net1",
				NetworkDevice: infrav1alpha1.NetworkDevice{Bridge: "vmbr1", Model: ptr.To("virtio"), MTU: ptr.To(uint16(1500))},
			},
		},
	}

	vm := newStoppedVM()
	task := newTask()
	machineScope.SetVirtualMachine(vm)
	expectedOptions := []interface{}{
		proxmox.VirtualMachineOption{Name: optionSockets, Value: machineScope.ProxmoxMachine.Spec.NumSockets},
		proxmox.VirtualMachineOption{Name: optionCores, Value: machineScope.ProxmoxMachine.Spec.NumCores},
		proxmox.VirtualMachineOption{Name: optionMemory, Value: machineScope.ProxmoxMachine.Spec.MemoryMiB},
		proxmox.VirtualMachineOption{Name: optionDescription, Value: machineScope.ProxmoxMachine.Spec.Description},
		proxmox.VirtualMachineOption{Name: "net0", Value: formatNetworkDevice("virtio", "vmbr0", ptr.To(uint16(1500)), nil)},
		proxmox.VirtualMachineOption{Name: "net1", Value: formatNetworkDevice("virtio", "vmbr1", ptr.To(uint16(1500)), nil)},
	}

	proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expectedOptions...).Return(task, nil).Once()

	requeue, err := reconcileVirtualMachineConfig(context.Background(), machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
	require.EqualValues(t, task.UPID, *machineScope.ProxmoxMachine.Status.TaskRef)
}

func TestReconcileVirtualMachineConfig_PCIDevices(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.ProxmoxMachine.Spec.NumSockets = 2
	machineScope.ProxmoxMachine.Spec.NumCores = 2
	machineScope.ProxmoxMachine.Spec.MemoryMiB = 2048
	machineScope.ProxmoxMachine.Spec.Description = ptr.To("test")
	machineScope.ProxmoxMachine.Spec.PCIDevices = []infrav1alpha1.PCIDeviceSpec{{Mapping: "gpu0"}}

	vm := newStoppedVM()
	vm.VirtualMachineConfig.Sockets = 2
	vm.VirtualMachineConfig.Cores = 2
	vm.VirtualMachineConfig.Memory = 2048
	vm.VirtualMachineConfig.Description = "test"
	machineScope.SetVirtualMachine(vm)

	expectedOptions := []interface{}{
		proxmox.VirtualMachineOption{Name: "hostpci0", Value: "mapping=gpu0,pcie=1"},
	}

	proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expectedOptions...).Return(newTask(), nil).Once()

	requeue, err := reconcileVirtualMachineConfig(context.Background(), machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
}

func TestReconcileVirtualMachineConfigTags(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	// CASE: Multiple tags
	machineScope.ProxmoxMachine.Spec.Tags = []string{"tag1", "tag2"}

	vm := newStoppedVM()
	vm.VirtualMachineConfig.Tags = "tag0"
	task := newTask()
	machineScope.SetVirtualMachine(vm)
	expectedOptions := []interface{}{
		proxmox.VirtualMachineOption{Name: optionTags, Value: "tag0;tag1;tag2"},
	}

	proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expectedOptions...).Return(task, nil).Once()

	requeue, err := reconcileVirtualMachineConfig(context.Background(), machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
	require.EqualValues(t, task.UPID, *machineScope.ProxmoxMachine.Status.TaskRef)

	// CASE: empty Tags
	machineScope.ProxmoxMachine.Spec.Tags = []string{}
	machineScope.ProxmoxMachine.Spec.Description = ptr.To("test vm")
	vm = newStoppedVM()
	vm.VirtualMachineConfig.Tags = "tag0"
	task = newTask()
	machineScope.SetVirtualMachine(vm)
	expectedOptions = []interface{}{
		proxmox.VirtualMachineOption{Name: optionDescription, Value: machineScope.ProxmoxMachine.Spec.Description},
	}

	proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expectedOptions...).Return(task, nil).Once()

	requeue, err = reconcileVirtualMachineConfig(context.Background(), machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
	require.EqualValues(t, task.UPID, *machineScope.ProxmoxMachine.Status.TaskRef)
}

func TestReconcileDisks_RunningVM(t *testing.T) {
	machineScope, _, _ := setupReconcilerTest(t)
	machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
		BootVolume: &infrav1alpha1.DiskSpec{Disk: "ide0", SizeGB: 100},
	}
	machineScope.SetVirtualMachine(newRunningVM())

	require.NoError(t, reconcileDisks(context.Background(), machineScope))
}

func TestReconcileDisks_ResizeDisk(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
		BootVolume: &infrav1alpha1.DiskSpec{Disk: "ide0", SizeGB: 100},
	}
	vm := newStoppedVM()
	machineScope.SetVirtualMachine(vm)

	task := newTask()
	proxmoxClient.EXPECT().ResizeDisk(context.Background(), vm, "ide0", machineScope.ProxmoxMachine.Spec.Disks.BootVolume.FormatSize()).Return(task, nil)

	require.NoError(t, reconcileDisks(context.Background(), machineScope))
}

func TestReconcileVirtualMachineConfig_AdditionalVolumes(t *testing.T) {
	ctx := context.Background()

	// 1) Block-backed syntax when no formats are specified
	{
		machineScope, proxmoxClient, _ := setupReconcilerTest(t)

		vm := newStoppedVM()
		vm.VirtualMachineConfig.Sockets = 2
		vm.VirtualMachineConfig.Cores = 1
		machineScope.SetVirtualMachine(vm)

		// Machine-level format present, but NO per-volume format -> should still use BLOCK syntax
		storage := "nfs-templates"
		machineScope.ProxmoxMachine.Spec.Storage = &storage

		rawFmt := infrav1alpha1.TargetFileStorageFormat("raw")
		machineScope.ProxmoxMachine.Spec.Format = &rawFmt // ignored for additional volumes
		machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
			AdditionalVolumes: []infrav1alpha1.DiskSpec{
				{Disk: "scsi1", SizeGB: 50}, // no per-volume format
			},
		}

		// Expect "<storage>:<size>" (block-backed syntax - no 'G', no format)
		expectedOptions := []interface{}{
			proxmox.VirtualMachineOption{
				Name:  "scsi1",
				Value: "nfs-templates:50",
			},
		}
		proxmoxClient.
			EXPECT().
			ConfigureVM(ctx, vm, expectedOptions...).
			Return(newTask(), nil).
			Once()

		requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
		require.NoError(t, err)
		require.True(t, requeue, "ConfigureVM should queue follow-up while task completes")
	}

	// 2) File-backed syntax with per-volume format (per-volume overrides machine-level)
	{
		machineScope, proxmoxClient, _ := setupReconcilerTest(t)

		vm := newStoppedVM()
		vm.VirtualMachineConfig.Sockets = 2
		vm.VirtualMachineConfig.Cores = 1
		machineScope.SetVirtualMachine(vm)

		storage := "nfs-store" // name only used in value rendering; presence of format selects file-backed syntax
		machineScope.ProxmoxMachine.Spec.Storage = &storage

		perVolFmt := infrav1alpha1.TargetFileStorageFormat("qcow2")
		machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
			AdditionalVolumes: []infrav1alpha1.DiskSpec{
				{Disk: "scsi2", SizeGB: 80, Format: &perVolFmt},
			},
		}

		// Expect "<storage>:0,size=<N>G,format=<fmt>" (file-backed)
		expectedOptions := []interface{}{
			proxmox.VirtualMachineOption{
				Name:  "scsi2",
				Value: "nfs-store:0,size=80G,format=qcow2",
			},
		}
		proxmoxClient.
			EXPECT().
			ConfigureVM(ctx, vm, expectedOptions...).
			Return(newTask(), nil).
			Once()

		requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
		require.NoError(t, err)
		require.True(t, requeue)
	}

	// 3) File-backed syntax with machine-level format fallback (no per-volume format)
	{
		machineScope, proxmoxClient, _ := setupReconcilerTest(t)

		vm := newStoppedVM()
		vm.VirtualMachineConfig.Sockets = 2
		vm.VirtualMachineConfig.Cores = 1
		machineScope.SetVirtualMachine(vm)

		storage := "nfs-store"
		machineScope.ProxmoxMachine.Spec.Storage = &storage

		machineFmt := infrav1alpha1.TargetFileStorageFormat("raw")
		machineScope.ProxmoxMachine.Spec.Format = &machineFmt
		machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
			AdditionalVolumes: []infrav1alpha1.DiskSpec{
				{Disk: "scsi3", SizeGB: 200}, // no per-volume format
			},
		}

		expectedOptions := []interface{}{
			proxmox.VirtualMachineOption{
				Name:  "scsi3",
				Value: "nfs-store:200",
			},
		}
		proxmoxClient.
			EXPECT().
			ConfigureVM(ctx, vm, expectedOptions...).
			Return(newTask(), nil).
			Once()

		requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
		require.NoError(t, err)
		require.True(t, requeue)
	}
}

func TestReconcileVirtualMachineConfig_AdditionalVolumes_Block_NoFormat(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	vm := newStoppedVM()
	machineScope.SetVirtualMachine(vm)

	// Machine-level storage is block-backed (e.g., LVM-thin); no format anywhere.
	storage := "local-lvm"
	machineScope.ProxmoxMachine.Spec.Storage = &storage
	machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
		AdditionalVolumes: []infrav1alpha1.DiskSpec{
			{Disk: "scsi1", SizeGB: 90}, // no per-volume format/storage
		},
	}

	// Expect block syntax "<storage>:<N>"
	expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi1", Value: "local-lvm:90"}}
	proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()

	requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
}

func TestReconcileVirtualMachineConfig_AdditionalVolumes_File_PerVolumeFormatAndStorage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	vm := newStoppedVM()
	machineScope.SetVirtualMachine(vm)

	// Per-volume specifies file-backed storage and format.
	nfs := "nfs-store"
	qcow2 := infrav1alpha1.TargetFileStorageFormat("qcow2")
	machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
		AdditionalVolumes: []infrav1alpha1.DiskSpec{
			{Disk: "scsi1", SizeGB: 80, Storage: &nfs, Format: &qcow2},
		},
	}

	// Expect file syntax "<storage>:0,size=NG,format=fmt"
	expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi1", Value: "nfs-store:0,size=80G,format=qcow2"}}
	proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()

	requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
}

func TestReconcileVirtualMachineConfig_AdditionalVolumes_File_MachineFormatUsedWhenPerVolumeMissing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	vm := newStoppedVM()
	machineScope.SetVirtualMachine(vm)

	// Machine-level format present -> file syntax.
	nfs := "nfs-templates"
	format := infrav1alpha1.TargetFileStorageFormat("raw")
	machineScope.ProxmoxMachine.Spec.Format = &format
	machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
		AdditionalVolumes: []infrav1alpha1.DiskSpec{
			{Disk: "scsi2", SizeGB: 50, Storage: &nfs}, // no per-volume format
		},
	}
	expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi2", Value: "nfs-templates:50"}}
	proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()
	requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
}

func TestReconcileVirtualMachineConfig_AdditionalVolumes_PerVolumeStorageOverridesMachine(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	vm := newStoppedVM()
	machineScope.SetVirtualMachine(vm)

	// Machine-level storage is block; per-volume chooses file store + format.
	machineStorage := "local-lvm"
	perVolStore := "nfs-a"
	perVolFmt := infrav1alpha1.TargetFileStorageFormat("qcow2")
	machineScope.ProxmoxMachine.Spec.Storage = &machineStorage
	machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
		AdditionalVolumes: []infrav1alpha1.DiskSpec{
			{Disk: "scsi1", SizeGB: 30, Storage: &perVolStore, Format: &perVolFmt},
		},
	}

	expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi1", Value: "nfs-a:0,size=30G,format=qcow2"}}
	proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()

	requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
}

func TestReconcileVirtualMachineConfig_AdditionalVolumes_AutoSelectsStorageWhenNoStorageAnywhere(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	vm := newStoppedVM()
	machineScope.SetVirtualMachine(vm)

	// The node the VM is running on – required so reconcileAdditionalVolumes
	// knows which node to query for local storage.
	nodeName := "node1"
	machineScope.ProxmoxMachine.Status.ProxmoxNode = ptr.To(nodeName)

	// No machine-level storage, no per-volume storage -> should auto-select
	// a suitable local storage pool on node1 instead of erroring.
	machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
		AdditionalVolumes: []infrav1alpha1.DiskSpec{
			{
				Disk:   "scsi1",
				SizeGB: 10,
				// Storage: nil
				// Format:  nil
			},
		},
	}

	// Storage status returned by Proxmox for node1.
	// Both are local, enabled, active, and support 'images'.
	storages := []proxmox.StorageStatus{
		{
			Name:         "local-small",
			Avail:        10 * 1024 * 1024 * 1024, // smaller
			VirtualAvail: 10 * 1024 * 1024 * 1024,
			Content:      "images",
			Enabled:      true,
			Active:       true,
			Shared:       false,
		},
		{
			Name:         "local-big",
			Avail:        20 * 1024 * 1024 * 1024, // larger -> should be chosen for additionalVolumes
			VirtualAvail: 20 * 1024 * 1024 * 1024,
			Content:      "images,rootdir",
			Enabled:      true,
			Active:       true,
			Shared:       false,
		},
	}

	// Expect the VM service to ask Proxmox for local storage status on node1.
	proxmoxClient.EXPECT().
		ListNodeStorages(ctx, nodeName).
		Return(storages, nil).
		Once()

	// With no format specified, additional volumes use the "block" syntax:
	// "<storage>:<sizeGB>".
	//
	// selectNodeStorages picks the storage with the highest virtual available
	// capacity (VirtualAvail) for additional volumes, which here is "local-big".
	expected := []interface{}{
		proxmox.VirtualMachineOption{
			Name:  "scsi1",
			Value: "local-big:10",
		},
	}

	proxmoxClient.EXPECT().
		ConfigureVM(context.Background(), vm, expected...).
		Return(newTask(), nil).
		Once()

	requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
}

func TestReconcileVirtualMachineConfig_AdditionalVolumes_IdempotentWhenSlotOccupied(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	machineScope, _, _ := setupReconcilerTest(t)

	vm := newStoppedVM()
	// Pretend scsi1 is already populated in VM config — reconcile should NOT call ConfigureVM.
	vm.VirtualMachineConfig.SCSI1 = "local-lvm:20"
	machineScope.SetVirtualMachine(vm)

	storage := "local-lvm"
	machineScope.ProxmoxMachine.Spec.Storage = &storage
	machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
		AdditionalVolumes: []infrav1alpha1.DiskSpec{
			{Disk: "scsi1", SizeGB: 40},
		},
	}

	// No EXPECT() on proxmoxClient.ConfigureVM — any call would be an unexpected invocation and fail the test.
	requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
	require.NoError(t, err)
	require.False(t, requeue, "reconcile should be a no-op when slot already occupied")
}
func TestReconcileVirtualMachineConfig_AdditionalVolumes_Block_DiscardTrue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	vm := newStoppedVM()
	machineScope.SetVirtualMachine(vm)

	storage := "local-lvm"
	machineScope.ProxmoxMachine.Spec.Storage = &storage
	dTrue := true
	machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
		AdditionalVolumes: []infrav1alpha1.DiskSpec{
			{Disk: "scsi1", SizeGB: 90, Discard: &dTrue},
		},
	}

	// Expect block syntax with ",discard=on" appended.
	expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi1", Value: "local-lvm:90,discard=on"}}
	proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()

	requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
}

func TestReconcileVirtualMachineConfig_AdditionalVolumes_File_PerVolumeFormat_DiscardTrue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	vm := newStoppedVM()
	machineScope.SetVirtualMachine(vm)

	nfs := "nfs-store"
	qcow2 := infrav1alpha1.TargetFileStorageFormat("qcow2")
	dTrue := true
	machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
		AdditionalVolumes: []infrav1alpha1.DiskSpec{
			{Disk: "scsi2", SizeGB: 80, Storage: &nfs, Format: &qcow2, Discard: &dTrue},
		},
	}

	// Expect file syntax with ",discard=on" appended.
	expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi2", Value: "nfs-store:0,size=80G,format=qcow2,discard=on"}}
	proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()

	requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
}

func TestReconcileVirtualMachineConfig_AdditionalVolumes_DiscardOmittedWhenNilOrFalse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Case A: discard=nil -> omitted
	{
		machineScope, proxmoxClient, _ := setupReconcilerTest(t)
		vm := newStoppedVM()
		machineScope.SetVirtualMachine(vm)

		storage := "local-lvm"
		machineScope.ProxmoxMachine.Spec.Storage = &storage
		// discard not set (nil)
		machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
			AdditionalVolumes: []infrav1alpha1.DiskSpec{
				{Disk: "scsi3", SizeGB: 20},
			},
		}

		expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi3", Value: "local-lvm:20"}}
		proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()

		requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
		require.NoError(t, err)
		require.True(t, requeue)
	}

	// Case B: discard=false -> omitted (we only emit when explicitly true)
	{
		machineScope, proxmoxClient, _ := setupReconcilerTest(t)
		vm := newStoppedVM()
		machineScope.SetVirtualMachine(vm)

		storage := "local-lvm"
		machineScope.ProxmoxMachine.Spec.Storage = &storage
		dFalse := false
		machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
			AdditionalVolumes: []infrav1alpha1.DiskSpec{
				{Disk: "scsi4", SizeGB: 25, Discard: &dFalse},
			},
		}

		expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi4", Value: "local-lvm:25"}}
		proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()

		requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
		require.NoError(t, err)
		require.True(t, requeue)
	}
}

func TestReconcileVirtualMachineConfig_AdditionalVolumes_Block_IothreadTrue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	vm := newStoppedVM()
	machineScope.SetVirtualMachine(vm)

	storage := "local-lvm"
	machineScope.ProxmoxMachine.Spec.Storage = &storage
	iTrue := true
	machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
		AdditionalVolumes: []infrav1alpha1.DiskSpec{
			{Disk: "scsi1", SizeGB: 90, IOThread: &iTrue},
		},
	}

	// Expect block syntax with ",ioThread=1" appended.
	expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi1", Value: "local-lvm:90,iothread=1"}}
	proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()

	requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
}

func TestReconcileVirtualMachineConfig_AdditionalVolumes_File_PerVolumeFormat_IothreadTrue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	vm := newStoppedVM()
	machineScope.SetVirtualMachine(vm)

	nfs := "nfs-store"
	qcow2 := infrav1alpha1.TargetFileStorageFormat("qcow2")
	iTrue := true
	machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
		AdditionalVolumes: []infrav1alpha1.DiskSpec{
			{Disk: "scsi2", SizeGB: 80, Storage: &nfs, Format: &qcow2, IOThread: &iTrue},
		},
	}

	// Expect file syntax with ",iothread=1" appended.
	expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi2", Value: "nfs-store:0,size=80G,format=qcow2,iothread=1"}}
	proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()

	requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
}

func TestReconcileVirtualMachineConfig_AdditionalVolumes_Iothread_OmittedWhenNilOrFalse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Case A: ioThread=nil -> omitted
	{
		machineScope, proxmoxClient, _ := setupReconcilerTest(t)
		vm := newStoppedVM()
		machineScope.SetVirtualMachine(vm)

		storage := "local-lvm"
		machineScope.ProxmoxMachine.Spec.Storage = &storage
		machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
			AdditionalVolumes: []infrav1alpha1.DiskSpec{
				{Disk: "scsi3", SizeGB: 20},
			},
		}

		expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi3", Value: "local-lvm:20"}}
		proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()

		requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
		require.NoError(t, err)
		require.True(t, requeue)
	}

	// Case B: ioThread=false -> omitted (only emit when explicitly true)
	{
		machineScope, proxmoxClient, _ := setupReconcilerTest(t)
		vm := newStoppedVM()
		machineScope.SetVirtualMachine(vm)

		storage := "local-lvm"
		machineScope.ProxmoxMachine.Spec.Storage = &storage
		iFalse := false
		machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
			AdditionalVolumes: []infrav1alpha1.DiskSpec{
				{Disk: "scsi4", SizeGB: 25, IOThread: &iFalse},
			},
		}

		expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi4", Value: "local-lvm:25"}}
		proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()

		requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
		require.NoError(t, err)
		require.True(t, requeue)
	}
}
func TestReconcileVirtualMachineConfig_AdditionalVolumes_Block_SSDTrue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	vm := newStoppedVM()
	machineScope.SetVirtualMachine(vm)

	storage := "local-lvm"
	machineScope.ProxmoxMachine.Spec.Storage = &storage
	sTrue := true
	machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
		AdditionalVolumes: []infrav1alpha1.DiskSpec{
			{Disk: "scsi1", SizeGB: 90, SSD: &sTrue},
		},
	}

	// Expect block syntax with ",ssd=1" appended.
	expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi1", Value: "local-lvm:90,ssd=1"}}
	proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()

	requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
}

func TestReconcileVirtualMachineConfig_AdditionalVolumes_File_PerVolumeFormat_SSDTrue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	vm := newStoppedVM()
	machineScope.SetVirtualMachine(vm)

	nfs := "nfs-store"
	qcow2 := infrav1alpha1.TargetFileStorageFormat("qcow2")
	sTrue := true
	machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
		AdditionalVolumes: []infrav1alpha1.DiskSpec{
			{Disk: "scsi2", SizeGB: 80, Storage: &nfs, Format: &qcow2, SSD: &sTrue},
		},
	}

	// Expect file syntax with ",ssd=1" appended.
	expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi2", Value: "nfs-store:0,size=80G,format=qcow2,ssd=1"}}
	proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()

	requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
}

func TestReconcileVirtualMachineConfig_AdditionalVolumes_SSD_OmittedWhenNilOrFalse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Case A: ssd=nil -> omitted
	{
		machineScope, proxmoxClient, _ := setupReconcilerTest(t)
		vm := newStoppedVM()
		machineScope.SetVirtualMachine(vm)

		storage := "local-lvm"
		machineScope.ProxmoxMachine.Spec.Storage = &storage
		machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
			AdditionalVolumes: []infrav1alpha1.DiskSpec{
				{Disk: "scsi3", SizeGB: 20},
			},
		}

		expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi3", Value: "local-lvm:20"}}
		proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()

		requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
		require.NoError(t, err)
		require.True(t, requeue)
	}

	// Case B: ssd=false -> omitted (only emit when explicitly true)
	{
		machineScope, proxmoxClient, _ := setupReconcilerTest(t)
		vm := newStoppedVM()
		machineScope.SetVirtualMachine(vm)

		storage := "local-lvm"
		machineScope.ProxmoxMachine.Spec.Storage = &storage
		sFalse := false
		machineScope.ProxmoxMachine.Spec.Disks = &infrav1alpha1.Storage{
			AdditionalVolumes: []infrav1alpha1.DiskSpec{
				{Disk: "scsi4", SizeGB: 25, SSD: &sFalse},
			},
		}

		expected := []interface{}{proxmox.VirtualMachineOption{Name: "scsi4", Value: "local-lvm:25"}}
		proxmoxClient.EXPECT().ConfigureVM(context.Background(), vm, expected...).Return(newTask(), nil).Once()

		requeue, err := reconcileVirtualMachineConfig(ctx, machineScope)
		require.NoError(t, err)
		require.True(t, requeue)
	}
}

func TestReconcileMachineAddresses_IPV4(t *testing.T) {
	machineScope, _, _ := setupReconcilerTest(t)
	vm := newRunningVM()
	machineScope.SetVirtualMachine(vm)
	machineScope.SetVirtualMachineID(int64(vm.VMID))
	machineScope.ProxmoxMachine.Status.IPAddresses = map[string]infrav1alpha1.IPAddress{infrav1alpha1.DefaultNetworkDevice: {IPV4: "10.10.10.10"}}
	machineScope.ProxmoxMachine.Status.BootstrapDataProvided = ptr.To(true)

	require.NoError(t, reconcileMachineAddresses(machineScope))
	require.Equal(t, machineScope.ProxmoxMachine.Status.Addresses[0].Address, machineScope.ProxmoxMachine.GetName())
	require.Equal(t, machineScope.ProxmoxMachine.Status.Addresses[1].Address, "10.10.10.10")
}

func TestReconcileMachineAddresses_IPV6(t *testing.T) {
	machineScope, _, _ := setupReconcilerTest(t)
	machineScope.InfraCluster.ProxmoxCluster.Spec.IPv4Config = nil
	machineScope.InfraCluster.ProxmoxCluster.Spec.IPv6Config = &infrav1alpha1.IPConfigSpec{
		Addresses: []string{"2001:db8::/64"},
		Prefix:    64,
		Gateway:   "2001:db8::1",
	}

	vm := newRunningVM()
	machineScope.SetVirtualMachine(vm)
	machineScope.SetVirtualMachineID(int64(vm.VMID))
	machineScope.ProxmoxMachine.Status.IPAddresses = map[string]infrav1alpha1.IPAddress{infrav1alpha1.DefaultNetworkDevice: {IPV6: "2001:db8::2"}}
	machineScope.ProxmoxMachine.Status.BootstrapDataProvided = ptr.To(true)

	require.NoError(t, reconcileMachineAddresses(machineScope))
	require.Equal(t, machineScope.ProxmoxMachine.Status.Addresses[0].Address, machineScope.ProxmoxMachine.GetName())
	require.Equal(t, machineScope.ProxmoxMachine.Status.Addresses[1].Address, "2001:db8::2")
}

func TestReconcileMachineAddresses_DualStack(t *testing.T) {
	machineScope, _, _ := setupReconcilerTest(t)
	machineScope.InfraCluster.ProxmoxCluster.Spec.IPv6Config = &infrav1alpha1.IPConfigSpec{
		Addresses: []string{"2001:db8::/64"},
		Prefix:    64,
		Gateway:   "2001:db8::1",
	}

	vm := newRunningVM()
	machineScope.SetVirtualMachine(vm)
	machineScope.SetVirtualMachineID(int64(vm.VMID))
	machineScope.ProxmoxMachine.Status.IPAddresses = map[string]infrav1alpha1.IPAddress{infrav1alpha1.DefaultNetworkDevice: {IPV4: "10.10.10.10", IPV6: "2001:db8::2"}}
	machineScope.ProxmoxMachine.Status.BootstrapDataProvided = ptr.To(true)

	require.NoError(t, reconcileMachineAddresses(machineScope))
	require.Equal(t, machineScope.ProxmoxMachine.Status.Addresses[0].Address, machineScope.ProxmoxMachine.GetName())
	require.Equal(t, machineScope.ProxmoxMachine.Status.Addresses[1].Address, "10.10.10.10")
	require.Equal(t, machineScope.ProxmoxMachine.Status.Addresses[2].Address, "2001:db8::2")
}

func TestReconcileVirtualMachineConfigVLAN(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	machineScope.ProxmoxMachine.Spec.NumSockets = 4
	machineScope.ProxmoxMachine.Spec.NumCores = 4
	machineScope.ProxmoxMachine.Spec.MemoryMiB = 16 * 1024
	machineScope.ProxmoxMachine.Spec.Network = &infrav1alpha1.NetworkSpec{
		Default: &infrav1alpha1.NetworkDevice{Bridge: "vmbr0", Model: ptr.To("virtio"), VLAN: ptr.To(uint16(100))},
		AdditionalDevices: []infrav1alpha1.AdditionalNetworkDevice{
			{
				Name:          "net1",
				NetworkDevice: infrav1alpha1.NetworkDevice{Bridge: "vmbr1", Model: ptr.To("virtio"), VLAN: ptr.To(uint16(100))},
			},
		},
	}

	vm := newStoppedVM()
	task := newTask()
	machineScope.SetVirtualMachine(vm)
	expectedOptions := []interface{}{
		proxmox.VirtualMachineOption{Name: optionSockets, Value: machineScope.ProxmoxMachine.Spec.NumSockets},
		proxmox.VirtualMachineOption{Name: optionCores, Value: machineScope.ProxmoxMachine.Spec.NumCores},
		proxmox.VirtualMachineOption{Name: optionMemory, Value: machineScope.ProxmoxMachine.Spec.MemoryMiB},
		proxmox.VirtualMachineOption{Name: "net0", Value: formatNetworkDevice("virtio", "vmbr0", nil, ptr.To(uint16(100)))},
		proxmox.VirtualMachineOption{Name: "net1", Value: formatNetworkDevice("virtio", "vmbr1", nil, ptr.To(uint16(100)))},
	}

	proxmoxClient.EXPECT().ConfigureVM(context.TODO(), vm, expectedOptions...).Return(task, nil).Once()

	requeue, err := reconcileVirtualMachineConfig(context.TODO(), machineScope)
	require.NoError(t, err)
	require.True(t, requeue)
	require.EqualValues(t, task.UPID, *machineScope.ProxmoxMachine.Status.TaskRef)
}

func TestReconcileDisks_UnmountCloudInitISO(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	vm := newRunningVM()
	vm.VirtualMachineConfig.IDE0 = "local:iso/cloud-init.iso,media=cdrom"
	machineScope.SetVirtualMachine(vm)

	proxmoxClient.EXPECT().UnmountCloudInitISO(context.Background(), vm, "ide0").Return(nil)

	require.NoError(t, unmountCloudInitISO(context.Background(), machineScope))
}

func TestReconcileVM_CloudInitFailed(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	vm := newRunningVM()
	machineScope.SetVirtualMachineID(int64(vm.VMID))
	machineScope.ProxmoxMachine.Status.IPAddresses = map[string]infrav1alpha1.IPAddress{infrav1alpha1.DefaultNetworkDevice: {IPV4: "10.10.10.10"}}
	machineScope.ProxmoxMachine.Status.BootstrapDataProvided = ptr.To(true)
	machineScope.ProxmoxMachine.Status.Ready = true
	machineScope.ProxmoxMachine.Spec.VirtualMachineCloneSpec = infrav1alpha1.VirtualMachineCloneSpec{
		TemplateSource: infrav1alpha1.TemplateSource{
			SourceNode: "node1",
			TemplateID: ptr.To[int32](123),
		},
	}

	proxmoxClient.EXPECT().GetVM(context.Background(), "node1", int64(123)).Return(vm, nil).Once()
	proxmoxClient.EXPECT().CloudInitStatus(context.Background(), vm).Return(false, goproxmox.ErrCloudInitFailed).Once()
	proxmoxClient.EXPECT().QemuAgentStatus(context.Background(), vm).Return(nil).Once()

	_, err := ReconcileVM(context.Background(), machineScope)
	require.Error(t, err, "unknown error")
	require.Equal(t, machineScope.ProxmoxMachine.Status.FailureReason, ptr.To(capierrors.MachineStatusError("BootstrapFailed")))
	require.Equal(t, machineScope.ProxmoxMachine.Status.FailureMessage, ptr.To("cloud-init failed execution"))
}

func TestReconcileVM_CloudInitRunning(t *testing.T) {
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)
	vm := newRunningVM()
	machineScope.SetVirtualMachineID(int64(vm.VMID))
	machineScope.ProxmoxMachine.Status.IPAddresses = map[string]infrav1alpha1.IPAddress{infrav1alpha1.DefaultNetworkDevice: {IPV4: "10.10.10.10"}}
	machineScope.ProxmoxMachine.Status.BootstrapDataProvided = ptr.To(true)
	machineScope.ProxmoxMachine.Status.Ready = true
	machineScope.ProxmoxMachine.Spec.VirtualMachineCloneSpec = infrav1alpha1.VirtualMachineCloneSpec{
		TemplateSource: infrav1alpha1.TemplateSource{
			SourceNode: "node1",
			TemplateID: ptr.To[int32](123),
		},
	}

	proxmoxClient.EXPECT().GetVM(context.Background(), "node1", int64(123)).Return(vm, nil).Once()
	proxmoxClient.EXPECT().CloudInitStatus(context.Background(), vm).Return(true, nil).Once()
	proxmoxClient.EXPECT().QemuAgentStatus(context.Background(), vm).Return(nil).Once()

	result, err := ReconcileVM(context.Background(), machineScope)
	require.NoError(t, err)
	require.Equal(t, infrav1alpha1.VirtualMachineStatePending, result.State)
}

// ---- tests for persisted storage selection (vm_test.go) ----
// These tests belong in internal/service/vmservice/vm_test.go.

func TestEnsureStorageSelection_ReusesPersistedSelection(t *testing.T) {
	ctx := context.Background()
	machineScope, _, _ := setupReconcilerTest(t)

	pm := machineScope.ProxmoxMachine
	pm.Spec.Disks = &infrav1alpha1.Storage{
		BootVolume: &infrav1alpha1.DiskSpec{Disk: "scsi0", SizeGB: 50},
	}
	disksHash := disksSpecHash(pm.Spec.Disks)

	pm.Status.StorageSelection = &infrav1alpha1.StorageSelectionStatus{
		Node:              "node1",
		BootStorage:       "boot-a",
		AdditionalStorage: "data-b",
		DisksHash:         disksHash,
	}

	boot, additional, err := ensureStorageSelection(ctx, machineScope, "node1")
	require.NoError(t, err)
	require.Equal(t, "boot-a", boot)
	require.Equal(t, "data-b", additional)
}

func TestEnsureStorageSelection_RecomputesWhenDisksChange(t *testing.T) {
	ctx := context.Background()
	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	nodeName := "node1"
	pm := machineScope.ProxmoxMachine

	// Initial selection recorded with a different disks hash.
	pm.Status.StorageSelection = &infrav1alpha1.StorageSelectionStatus{
		Node:              nodeName,
		BootStorage:       "old-boot",
		AdditionalStorage: "old-data",
		DisksHash:         "stale-hash",
	}

	// Current disks spec differs -> ensureStorageSelection should recompute
	// using selectNodeStorages and update the status.
	pm.Spec.Disks = &infrav1alpha1.Storage{
		BootVolume: &infrav1alpha1.DiskSpec{Disk: "scsi0", SizeGB: 10},
	}

	storages := []proxmox.StorageStatus{
		{
			Name:    "local-foo",
			Enabled: true,
			Active:  true,
			Shared:  false,
			Content: "images",
			Avail:   1 << 40,
		},
	}

	proxmoxClient.EXPECT().
		ListNodeStorages(ctx, nodeName).
		Return(storages, nil).
		Once()

	boot, additional, err := ensureStorageSelection(ctx, machineScope, nodeName)
	require.NoError(t, err)
	require.Equal(t, "local-foo", boot)
	require.Equal(t, "local-foo", additional)

	hashNow := disksSpecHash(pm.Spec.Disks)
	require.NotNil(t, pm.Status.StorageSelection)
	require.Equal(t, nodeName, pm.Status.StorageSelection.Node)
	require.Equal(t, "local-foo", pm.Status.StorageSelection.BootStorage)
	require.Equal(t, "local-foo", pm.Status.StorageSelection.AdditionalStorage)
	require.Equal(t, hashNow, pm.Status.StorageSelection.DisksHash)
}

func TestSelectNodeStorages_RespectsReservedUsage(t *testing.T) {
	ctx := context.Background()

	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	nodeName := "node1"
	pm := machineScope.ProxmoxMachine
	pm.Spec.Disks = &infrav1alpha1.Storage{
		BootVolume:        &infrav1alpha1.DiskSpec{Disk: "scsi0", SizeGB: 10},
		AdditionalVolumes: []infrav1alpha1.DiskSpec{{Disk: "scsi1", SizeGB: 20}},
	}
	// Two storages with same VirtualAvail, but one has reserved usage of 20GB from another machine.
	storages := []proxmox.StorageStatus{
		{
			Name:         "ssd_a",
			Enabled:      true,
			Active:       true,
			Shared:       false,
			Content:      "images",
			Avail:        100 << 30, // 100 GiB physical free
			VirtualAvail: 80 << 30,  // 80 GiB effective free
		},
		{
			Name:         "ssd_b",
			Enabled:      true,
			Active:       true,
			Shared:       false,
			Content:      "images",
			Avail:        100 << 30, // 100 GiB physical free
			VirtualAvail: 100 << 30, // 100 GiB effective free
		},
	}

	proxmoxClient.EXPECT().ListNodeStorages(ctx, nodeName).Return(storages, nil).Once()

	boot, add, err := selectNodeStorages(ctx, machineScope, nodeName)
	require.NoError(t, err)

	// Because ssd_a has 20GB reserved, ssd_b should be chosen for additional.
	require.Equal(t, "ssd_b", add)
	// Boot should be next best (ssd_a).
	require.Equal(t, "ssd_a", boot)
}

func TestSelectNodeStorages_BootOnly_UsesBestPool(t *testing.T) {
	ctx := context.Background()

	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	nodeName := "node1"
	pm := machineScope.ProxmoxMachine
	pm.Spec.Disks = &infrav1alpha1.Storage{
		BootVolume: &infrav1alpha1.DiskSpec{Disk: "scsi0", SizeGB: 50},
	}

	storages := []proxmox.StorageStatus{
		{
			Name:         "slow",
			Enabled:      true,
			Active:       true,
			Shared:       false,
			Content:      "images",
			Avail:        100 << 30,
			VirtualAvail: 100 << 30,
		},
		{
			Name:         "fast",
			Enabled:      true,
			Active:       true,
			Shared:       false,
			Content:      "images",
			Avail:        200 << 30,
			VirtualAvail: 200 << 30,
		},
	}

	proxmoxClient.EXPECT().ListNodeStorages(ctx, nodeName).Return(storages, nil).Once()

	boot, add, err := selectNodeStorages(ctx, machineScope, nodeName)
	require.NoError(t, err)
	require.Equal(t, "fast", boot)
	require.Equal(t, "fast", add)
}

func TestSelectNodeStorages_BootOnly_NoSize_UsesBestPool(t *testing.T) {
	ctx := context.Background()

	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	nodeName := "node1"
	pm := machineScope.ProxmoxMachine
	pm.Spec.Disks = &infrav1alpha1.Storage{
		BootVolume: &infrav1alpha1.DiskSpec{Disk: "scsi0"},
	}

	storages := []proxmox.StorageStatus{
		{
			Name:         "slow",
			Enabled:      true,
			Active:       true,
			Shared:       false,
			Content:      "images",
			Avail:        100 << 30,
			VirtualAvail: 100 << 30,
		},
		{
			Name:         "fast",
			Enabled:      true,
			Active:       true,
			Shared:       false,
			Content:      "images",
			Avail:        200 << 30,
			VirtualAvail: 200 << 30,
		},
	}

	proxmoxClient.EXPECT().ListNodeStorages(ctx, nodeName).Return(storages, nil).Once()

	boot, add, err := selectNodeStorages(ctx, machineScope, nodeName)
	require.NoError(t, err)
	require.Equal(t, "fast", boot)
	require.Equal(t, "fast", add)
}

func TestSelectNodeStorages_AdditionalTooBig_ReturnsError(t *testing.T) {
	ctx := context.Background()

	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	nodeName := "node1"
	pm := machineScope.ProxmoxMachine
	pm.Spec.Disks = &infrav1alpha1.Storage{
		BootVolume:        &infrav1alpha1.DiskSpec{Disk: "scsi0", SizeGB: 10},
		AdditionalVolumes: []infrav1alpha1.DiskSpec{{Disk: "scsi1", SizeGB: 3000}},
	}

	storages := []proxmox.StorageStatus{
		{
			Name:         "store1",
			Enabled:      true,
			Active:       true,
			Shared:       false,
			Content:      "images",
			Avail:        100 << 30,
			VirtualAvail: 100 << 30,
		},
	}

	proxmoxClient.EXPECT().ListNodeStorages(ctx, nodeName).Return(storages, nil).Once()

	_, _, err := selectNodeStorages(ctx, machineScope, nodeName)
	require.Error(t, err)
	require.Contains(t, err.Error(), "additional volumes")
}

func TestSelectNodeStorages_BootTooBig_ReturnsError(t *testing.T) {
	ctx := context.Background()

	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	nodeName := "node1"
	pm := machineScope.ProxmoxMachine
	pm.Spec.Disks = &infrav1alpha1.Storage{
		BootVolume: &infrav1alpha1.DiskSpec{Disk: "scsi0", SizeGB: 3000},
	}

	storages := []proxmox.StorageStatus{
		{
			Name:         "store1",
			Enabled:      true,
			Active:       true,
			Shared:       false,
			Content:      "images",
			Avail:        100 << 30,
			VirtualAvail: 100 << 30,
		},
	}

	proxmoxClient.EXPECT().ListNodeStorages(ctx, nodeName).Return(storages, nil).Once()

	_, _, err := selectNodeStorages(ctx, machineScope, nodeName)
	require.Error(t, err)
	require.Contains(t, err.Error(), "boot volume")
}

func TestSelectNodeStorages_FallsBackToAvailWhenVirtualZero(t *testing.T) {
	ctx := context.Background()

	machineScope, proxmoxClient, _ := setupReconcilerTest(t)

	nodeName := "node1"
	pm := machineScope.ProxmoxMachine
	pm.Spec.Disks = &infrav1alpha1.Storage{
		BootVolume: &infrav1alpha1.DiskSpec{Disk: "scsi0", SizeGB: 10},
	}

	storages := []proxmox.StorageStatus{
		{
			Name:         "thin",
			Enabled:      true,
			Active:       true,
			Shared:       false,
			Content:      "images",
			Avail:        100 << 30,
			VirtualAvail: 0,
		},
		{
			Name:         "dir",
			Enabled:      true,
			Active:       true,
			Shared:       false,
			Content:      "images",
			Avail:        20 << 30,
			VirtualAvail: 20 << 30,
		},
	}

	proxmoxClient.EXPECT().ListNodeStorages(ctx, nodeName).Return(storages, nil).Once()

	boot, add, err := selectNodeStorages(ctx, machineScope, nodeName)
	require.NoError(t, err)
	require.Equal(t, "thin", boot)
	require.Equal(t, "thin", add)
}
