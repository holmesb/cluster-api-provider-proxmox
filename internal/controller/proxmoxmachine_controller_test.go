/*
Copyright 2024-2026 IONOS Cloud.

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

package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	"sigs.k8s.io/cluster-api/util/conditions"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	infrav1alpha1 "github.com/ionos-cloud/cluster-api-provider-proxmox/api/v1alpha1"
	infrav1 "github.com/ionos-cloud/cluster-api-provider-proxmox/api/v1alpha2"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/kubernetes/ipam"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/scope"
)

var _ = Describe("ProxmoxMachineReconciler", func() {
	BeforeEach(func() {})
	AfterEach(func() {})

	Context("Reconcile an ProxmoxMachine", func() {
		It("should not error with minimal set up", func() {
			reconciler := &ProxmoxMachineReconciler{
				Client:        k8sClient,
				Scheme:        runtime.NewScheme(),
				ProxmoxClient: proxmoxClient,
			}
			By("Calling reconcile")
			ctx := context.Background()
			instance := &infrav1.ProxmoxMachine{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "default"}}
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: client.ObjectKey{
					Namespace: instance.Namespace,
					Name:      instance.Name,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeZero())
		})
	})

	Context("PCI device request reconciliation", func() {
		It("should resume the VM lifecycle after all PCI claims are bound", func() {
			ctx := context.Background()
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(clusterv1.AddToScheme(scheme)).To(Succeed())
			Expect(infrav1alpha1.AddToScheme(scheme)).To(Succeed())
			Expect(infrav1.AddToScheme(scheme)).To(Succeed())

			cluster := &clusterv1.Cluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
			}
			machine := &clusterv1.Machine{
				ObjectMeta: metav1.ObjectMeta{Name: "gpu-worker-abc", Namespace: "default", UID: types.UID("machine-uid")},
			}
			pm := &infrav1.ProxmoxMachine{
				ObjectMeta: metav1.ObjectMeta{Name: "gpu-worker-abc", Namespace: "default"},
				Spec: infrav1.ProxmoxMachineSpec{
					PCIDeviceRequests: []infrav1.PCIDeviceRequest{
						{
							Name:       "gpu",
							PCIExpress: ptr.To(true),
							Selector: metav1.LabelSelector{
								MatchLabels: map[string]string{"model_key": "10de:1f01"},
							},
						},
					},
				},
			}
			conditions.Set(pm, metav1.Condition{
				Type:    infrav1.ProxmoxMachineVirtualMachineProvisionedCondition,
				Status:  metav1.ConditionFalse,
				Reason:  "WaitingForPCIDevices",
				Message: "waiting for PCI device claim gpu-worker-abc-gpu-0 to bind",
			})

			claim := &infrav1alpha1.ProxmoxPCIDeviceClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gpu-worker-abc-gpu-0",
					Namespace: "default",
					Labels: map[string]string{
						pciClaimLabelProxmoxMachine: "gpu-worker-abc",
						pciClaimLabelClusterName:    "test",
					},
				},
				Spec: infrav1alpha1.ProxmoxPCIDeviceClaimSpec{
					ClusterName: "test",
					Selector: metav1.LabelSelector{
						MatchLabels: map[string]string{"model_key": "10de:1f01"},
					},
				},
				Status: infrav1alpha1.ProxmoxPCIDeviceClaimStatus{
					Phase:          infrav1alpha1.ProxmoxPCIDeviceClaimPhaseBound,
					BoundMappingID: "gpu_10de_1f01_host01_01_00",
					ProxmoxNode:    "host01",
				},
			}
			proxmoxCluster := &infrav1.ProxmoxCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
			}

			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(cluster, machine, pm, claim, proxmoxCluster).
				Build()
			reconciler := &ProxmoxMachineReconciler{Client: c, Scheme: scheme}
			machineScope, err := scope.NewMachineScope(scope.MachineScopeParams{
				Client:         c,
				Cluster:        cluster,
				Machine:        machine,
				ProxmoxMachine: pm,
				InfraCluster:   &scope.ClusterScope{Cluster: cluster, ProxmoxCluster: proxmoxCluster},
				IPAMHelper:     ipam.NewHelper(c, proxmoxCluster),
			})
			Expect(err).NotTo(HaveOccurred())

			result, err := reconciler.reconcilePCIDeviceRequests(ctx, machineScope)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeZero())

			Expect(pm.Status.ProxmoxNode).NotTo(BeNil())
			Expect(*pm.Status.ProxmoxNode).To(Equal("host01"))
			Expect(pm.Status.PCIDeviceAllocations).To(HaveLen(1))
			Expect(pm.Status.PCIDeviceAllocations[0].Name).To(Equal("gpu"))
			Expect(pm.Status.PCIDeviceAllocations[0].ClaimName).To(Equal("gpu-worker-abc-gpu-0"))
			Expect(pm.Status.PCIDeviceAllocations[0].Mapping).To(Equal("gpu_10de_1f01_host01_01_00"))
			Expect(pm.Status.PCIDeviceAllocations[0].ProxmoxNode).To(Equal("host01"))

			condition := conditions.Get(pm, infrav1.ProxmoxMachineVirtualMachineProvisionedCondition)
			Expect(condition).NotTo(BeNil())
			Expect(condition.Reason).To(Equal(infrav1.ProxmoxMachineVirtualMachineProvisionedCloningReason))
			Expect(condition.Status).To(Equal(metav1.ConditionFalse))
		})
	})
})
