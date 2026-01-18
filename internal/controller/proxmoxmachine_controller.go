/*
Copyright 2023-2024 IONOS Cloud.

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
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/util"
	"sigs.k8s.io/cluster-api/util/annotations"
	"sigs.k8s.io/cluster-api/util/conditions"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlutil "sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	infrav1alpha1 "github.com/ionos-cloud/cluster-api-provider-proxmox/api/v1alpha1"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/internal/service/scheduler"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/internal/service/taskservice"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/internal/service/vmservice"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/kubernetes/ipam"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/scope"
)

// ProxmoxMachineReconciler reconciles a ProxmoxMachine object.
type ProxmoxMachineReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	Recorder      record.EventRecorder
	ProxmoxClient proxmox.Client
}

// SetupWithManager sets up the controller with the Manager.
func (r *ProxmoxMachineReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&infrav1alpha1.ProxmoxMachine{}).
		Watches(
			&clusterv1.Machine{},
			handler.EnqueueRequestsFromMapFunc(util.MachineToInfrastructureMapFunc(infrav1alpha1.GroupVersion.WithKind(infrav1alpha1.ProxmoxMachineKind))),
		).
		Complete(r)
}

// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=proxmoxmachines,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=proxmoxmachines/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=proxmoxmachines/finalizers,verbs=update
// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=proxmoxpcideviceclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=proxmoxpcideviceclaims/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=proxmoxpcideviceclaims/finalizers,verbs=update
// +kubebuilder:rbac:groups=cluster.x-k8s.io,resources=machines;machines/status,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;update;patch

// +kubebuilder:rbac:groups=ipam.cluster.x-k8s.io,resources=ipaddresses,verbs=get;list;watch
// +kubebuilder:rbac:groups=ipam.cluster.x-k8s.io,resources=ipaddressclaims,verbs=get;list;watch;create;update;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.4/pkg/reconcile
func (r *ProxmoxMachineReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, reterr error) {
	logger := log.FromContext(ctx)

	// Fetch the ProxmoxMachine instance.
	proxmoxMachine := &infrav1alpha1.ProxmoxMachine{}
	err := r.Get(ctx, req.NamespacedName, proxmoxMachine)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Emit deprecation warning if .spec.Target is set
	if proxmoxMachine.Spec.Target != nil {
		logger.Info("DEPRECATION NOTICE: .spec.Target is deprecated and will be removed in a future release. Use .spec.AllowedNodes instead.",
			"ProxmoxMachine", req.NamespacedName)
	}

	// Fetch the Machine.
	machine, err := util.GetOwnerMachine(ctx, r.Client, proxmoxMachine.ObjectMeta)
	if err != nil {
		return ctrl.Result{}, err
	}
	if machine == nil {
		logger.Info("Machine Controller has not yet set OwnerRef")
		return ctrl.Result{}, nil
	}

	logger = logger.WithValues("machine", klog.KObj(machine))

	// Fetch the Cluster.
	cluster, err := util.GetClusterFromMetadata(ctx, r.Client, machine.ObjectMeta)
	if err != nil {
		logger.Info("Machine is missing cluster label or cluster does not exist")
		return ctrl.Result{}, nil
	}

	if annotations.IsPaused(cluster, proxmoxMachine) {
		logger.Info("ProxmoxMachine or linked Cluster is marked as paused, not reconciling")
		return ctrl.Result{}, nil
	}

	logger = logger.WithValues("cluster", klog.KObj(cluster))

	infraCluster, err := r.getInfraCluster(ctx, &logger, cluster, proxmoxMachine)
	if err != nil {
		return ctrl.Result{}, errors.Errorf("error getting infra provider cluster or control plane object: %v", err)
	}
	if infraCluster == nil {
		logger.Info("ProxmoxCluster is not ready yet")
		return ctrl.Result{}, nil
	}

	// Create the machine scope
	machineScope, err := scope.NewMachineScope(scope.MachineScopeParams{
		Client:         r.Client,
		Cluster:        cluster,
		Machine:        machine,
		InfraCluster:   infraCluster,
		ProxmoxMachine: proxmoxMachine,
		IPAMHelper:     ipam.NewHelper(r.Client, infraCluster.ProxmoxCluster),
		Logger:         &logger,
	})
	if err != nil {
		logger.Error(err, "failed to create scope")
		return ctrl.Result{}, err
	}

	// Always close the scope when exiting this function, so we can persist any ProxmoxMachine changes.
	defer func() {
		if err := machineScope.Close(); err != nil && reterr == nil {
			reterr = err
		}
	}()

	if !proxmoxMachine.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, machineScope)
	}

	return r.reconcileNormal(ctx, machineScope, infraCluster)
}

func (r *ProxmoxMachineReconciler) reconcileDelete(ctx context.Context, machineScope *scope.MachineScope) (ctrl.Result, error) {
	machineScope.Logger.Info("Handling deleted ProxmoxMachine")
	conditions.MarkFalse(machineScope.ProxmoxMachine, infrav1alpha1.VMProvisionedCondition, clusterv1.DeletingReason, clusterv1.ConditionSeverityInfo, "")

	err := vmservice.DeleteVM(ctx, machineScope)
	if err != nil {
		return reconcile.Result{}, err
	}
	machineScope.Logger.Info("VM delete requested; requeue until removed")
	return reconcile.Result{RequeueAfter: infrav1alpha1.DefaultReconcilerRequeue}, nil
}

func (r *ProxmoxMachineReconciler) reconcileNormal(ctx context.Context, machineScope *scope.MachineScope, clusterScope *scope.ClusterScope) (reconcile.Result, error) {
	clusterScope.Logger.V(4).Info("Reconciling ProxmoxMachine")

	// If the ProxmoxMachine is in an error state, return early.
	if machineScope.HasFailed() {
		machineScope.Info("Error state detected, skipping reconciliation")
		return ctrl.Result{}, nil
	}

	if !machineScope.Cluster.Status.InfrastructureReady {
		machineScope.Info("Cluster infrastructure is not ready yet")
		conditions.MarkFalse(machineScope.ProxmoxMachine, infrav1alpha1.VMProvisionedCondition, infrav1alpha1.WaitingForClusterInfrastructureReason, clusterv1.ConditionSeverityInfo, "")
		return ctrl.Result{}, nil
	}

	// Make sure bootstrap data is available and populated.
	if machineScope.Machine.Spec.Bootstrap.DataSecretName == nil {
		machineScope.Info("Bootstrap data secret reference is not yet available")
		conditions.MarkFalse(machineScope.ProxmoxMachine, infrav1alpha1.VMProvisionedCondition, infrav1alpha1.WaitingForBootstrapDataReason, clusterv1.ConditionSeverityInfo, "")
		return ctrl.Result{}, nil
	}

	// If the ProxmoxMachine doesn't have our finalizer, add it.
	if ctrlutil.AddFinalizer(machineScope.ProxmoxMachine, infrav1alpha1.MachineFinalizer) {
		// Register the finalizer after first read operation from Proxmox to avoid orphaning Proxmox resources on delete
		if err := machineScope.PatchObject(); err != nil {
			machineScope.Error(err, "unable to patch object")
			return ctrl.Result{}, err
		}
	}

	// Note: PCI placement is driven by device-claim binding (first claim picks a node),
	// not by the VM scheduler, so we don't pre-select a node here.

	// Ensure any requested PCI devices have been allocated before we finalise VM provisioning.
	if res, err := r.reconcilePCIDeviceRequests(ctx, machineScope); err != nil {
		return res, err
	} else if res.Requeue || res.RequeueAfter > 0 {
		return res, nil
	}

	// find the vm
	// Get or create the VM.
	vm, err := vmservice.ReconcileVM(ctx, machineScope)
	if err != nil {
		if requeueErr := new(taskservice.RequeueError); errors.As(err, &requeueErr) {
			machineScope.Error(err, "Requeue requested")
			return reconcile.Result{RequeueAfter: requeueErr.RequeueAfter()}, nil
		}
		machineScope.Logger.Error(err, "error reconciling VM")
		return reconcile.Result{}, errors.Wrapf(err, "failed to reconcile VM")
	}
	machineScope.ProxmoxMachine.Status.VMStatus = vm.State

	// Do not proceed until the backend VM is marked ready.
	if vm.State != infrav1alpha1.VirtualMachineStateReady {
		machineScope.Logger.Info(
			"VM state is not reconciled",
			"expectedVMState", infrav1alpha1.VirtualMachineStateReady,
			"actualVMState", vm.State)
		return reconcile.Result{RequeueAfter: infrav1alpha1.DefaultReconcilerRequeue}, nil
	}

	// TODO, check if we need to add some labels to the machine.

	machineScope.SetReady()
	conditions.MarkTrue(machineScope.ProxmoxMachine, infrav1alpha1.VMProvisionedCondition)
	machineScope.Logger.Info("ProxmoxMachine is ready")

	return reconcile.Result{}, nil
}

const (
	pciClaimLabelProxmoxMachine = "infrastructure.cluster.x-k8s.io/proxmoxmachine"
	pciClaimLabelClusterName    = "cluster.x-k8s.io/cluster-name"
)

func (r *ProxmoxMachineReconciler) ensureProxmoxNodeSelectedForPCIDevices(ctx context.Context, machineScope *scope.MachineScope) error {
	pm := machineScope.ProxmoxMachine
	if pm.Status.ProxmoxNode != nil && strings.TrimSpace(*pm.Status.ProxmoxNode) != "" {
		return nil
	}

	if machineScope.InfraCluster.ProxmoxCluster.Status.NodeLocations == nil {
		machineScope.InfraCluster.ProxmoxCluster.Status.NodeLocations = new(infrav1alpha1.NodeLocations)
	}

	localStorage := pm.GetLocalStorage()
	templateMap := pm.GetTemplateMap()

	allowedNodes := machineScope.InfraCluster.ProxmoxCluster.Spec.AllowedNodes
	if len(pm.Spec.AllowedNodes) > 0 {
		allowedNodes = pm.Spec.AllowedNodes
	}
	if pm.Spec.Target != nil && (len(pm.Spec.AllowedNodes) == 0 || len(machineScope.InfraCluster.ProxmoxCluster.Spec.AllowedNodes) == 0) {
		allowedNodes = []string{*pm.Spec.Target}
	}

	if templateMap == nil {
		tags := pm.GetTemplateSelectorTags()
		m, err := machineScope.InfraCluster.ProxmoxClient.FindVMTemplatesByTags(ctx, tags, allowedNodes, localStorage)
		if err != nil {
			return err
		}
		templateMap = m
	}

	node, _, err := scheduler.ScheduleVM(ctx, machineScope, templateMap, allowedNodes)
	if err != nil {
		return err
	}

	node = strings.TrimSpace(node)
	if node == "" {
		return fmt.Errorf("scheduler returned empty node")
	}

	nodeCopy := node
	pm.Status.ProxmoxNode = &nodeCopy
	machineScope.Logger.Info("selected Proxmox node for PCI allocation", "node", nodeCopy)
	return nil
}

func (r *ProxmoxMachineReconciler) reconcilePCIDeviceRequests(ctx context.Context, machineScope *scope.MachineScope) (ctrl.Result, error) {
	pm := machineScope.ProxmoxMachine
	if len(pm.Spec.PCIDeviceRequests) == 0 {
		return ctrl.Result{}, nil
	}

	clusterName := machineScope.Cluster.Name
	desired := map[string]struct{}{}

	preferredNode := ""
	if pm.Status.ProxmoxNode != nil {
		preferredNode = strings.TrimSpace(*pm.Status.ProxmoxNode)
	}

	// Claim-driven placement:
	// - If no node is chosen yet, bind the first claim without a preferred node.
	// - Once bound, adopt the claim's chosen node as pm.Status.ProxmoxNode.
	// - Then create/patch all remaining claims constrained to that node.
	if preferredNode == "" {
		req0 := pm.Spec.PCIDeviceRequests[0]
		placementName := claimNameFor(pm.Name, req0.Name, 0)

		placement := &infrav1alpha1.ProxmoxPCIDeviceClaim{}
		placement.Namespace = pm.Namespace
		placement.Name = placementName

		_, err := ctrlutil.CreateOrPatch(ctx, r.Client, placement, func() error {
			if placement.Labels == nil {
				placement.Labels = map[string]string{}
			}
			placement.Labels[pciClaimLabelProxmoxMachine] = pm.Name
			placement.Labels[pciClaimLabelClusterName] = clusterName

			placement.Spec.ClusterName = clusterName
			placement.Spec.Selector = req0.Selector
			// Intentionally no PreferredProxmoxNode here.
			placement.Spec.ConsumerRef = &corev1.ObjectReference{
				APIVersion: clusterv1.GroupVersion.String(),
				Kind:       "Machine",
				Name:       machineScope.Machine.Name,
				Namespace:  machineScope.Machine.Namespace,
				UID:        machineScope.Machine.UID,
			}
			return ctrlutil.SetControllerReference(pm, placement, r.Scheme)
		})
		if err != nil {
			machineScope.Logger.Error(err, "failed to create/patch placement ProxmoxPCIDeviceClaim", "claim", placementName)
			return ctrl.Result{}, err
		}

		// Re-read for status.
		if err := r.Get(ctx, types.NamespacedName{Namespace: pm.Namespace, Name: placementName}, placement); err != nil {
			return ctrl.Result{}, err
		}
		if placement.Status.BoundMappingID == "" || placement.Status.Phase != infrav1alpha1.ProxmoxPCIDeviceClaimPhaseBound {
			conditions.MarkFalse(pm, infrav1alpha1.VMProvisionedCondition, "WaitingForPCIDevices", clusterv1.ConditionSeverityInfo, "waiting for PCI device claim %s to bind", placementName)
			return ctrl.Result{RequeueAfter: infrav1alpha1.DefaultReconcilerRequeue}, nil
		}
		preferredNode = strings.TrimSpace(placement.Status.ProxmoxNode)
		if preferredNode == "" {
			return ctrl.Result{}, fmt.Errorf("placement claim %q bound without proxmox node", placementName)
		}
		nodeCopy := preferredNode
		pm.Status.ProxmoxNode = &nodeCopy
		machineScope.Logger.Info("adopted Proxmox node from PCI placement", "node", preferredNode)
	}

	// Create or update desired claims.
	for _, req := range pm.Spec.PCIDeviceRequests {
		count := int32(1)
		if req.Count != nil && *req.Count > 0 {
			count = *req.Count
		}
		for i := int32(0); i < count; i++ {
			claimName := claimNameFor(pm.Name, req.Name, i)
			desired[claimName] = struct{}{}

			claim := &infrav1alpha1.ProxmoxPCIDeviceClaim{}
			claim.Namespace = pm.Namespace
			claim.Name = claimName

			_, err := ctrlutil.CreateOrPatch(ctx, r.Client, claim, func() error {
				if claim.Labels == nil {
					claim.Labels = map[string]string{}
				}
				claim.Labels[pciClaimLabelProxmoxMachine] = pm.Name
				claim.Labels[pciClaimLabelClusterName] = clusterName

				claim.Spec.ClusterName = clusterName
				claim.Spec.Selector = req.Selector
				claim.Spec.PreferredProxmoxNode = preferredNode
				claim.Spec.ConsumerRef = &corev1.ObjectReference{
					APIVersion: clusterv1.GroupVersion.String(),
					Kind:       "Machine",
					Name:       machineScope.Machine.Name,
					Namespace:  machineScope.Machine.Namespace,
					UID:        machineScope.Machine.UID,
				}

				return ctrlutil.SetControllerReference(pm, claim, r.Scheme)
			})
			if err != nil {
				machineScope.Logger.Error(err, "failed to create/patch ProxmoxPCIDeviceClaim", "claim", claimName)
				return ctrl.Result{}, err
			}
		}
	}

	// Delete any old claims that no longer match the spec.
	var existing infrav1alpha1.ProxmoxPCIDeviceClaimList
	if err := r.List(ctx, &existing, client.InNamespace(pm.Namespace), client.MatchingLabels{pciClaimLabelProxmoxMachine: pm.Name, pciClaimLabelClusterName: clusterName}); err != nil {
		return ctrl.Result{}, err
	}
	for i := range existing.Items {
		c := &existing.Items[i]
		if _, ok := desired[c.Name]; ok {
			continue
		}
		_ = r.Delete(ctx, c)
	}

	// Collect allocations; if any claim isn't bound yet, requeue.
	allocs := make([]infrav1alpha1.PCIDeviceAllocation, 0)
	for _, req := range pm.Spec.PCIDeviceRequests {
		count := int32(1)
		if req.Count != nil && *req.Count > 0 {
			count = *req.Count
		}
		for i := int32(0); i < count; i++ {
			claimName := claimNameFor(pm.Name, req.Name, i)
			claim := &infrav1alpha1.ProxmoxPCIDeviceClaim{}
			if err := r.Get(ctx, types.NamespacedName{Namespace: pm.Namespace, Name: claimName}, claim); err != nil {
				return ctrl.Result{}, err
			}

			if claim.Status.BoundMappingID == "" || claim.Status.Phase != infrav1alpha1.ProxmoxPCIDeviceClaimPhaseBound {
				conditions.MarkFalse(pm, infrav1alpha1.VMProvisionedCondition, "WaitingForPCIDevices", clusterv1.ConditionSeverityInfo, "waiting for PCI device claim %s to bind", claimName)
				return ctrl.Result{RequeueAfter: infrav1alpha1.DefaultReconcilerRequeue}, nil
			}

			allocs = append(allocs, infrav1alpha1.PCIDeviceAllocation{
				Name:        req.Name,
				ClaimName:   claimName,
				Mapping:     claim.Status.BoundMappingID,
				ProxmoxNode: claim.Status.ProxmoxNode,
				PCIExpress:  req.PCIExpress,
			})
		}
	}

	pm.Status.PCIDeviceAllocations = allocs
	return ctrl.Result{}, nil
}

func claimNameFor(machineName, reqName string, idx int32) string {
	base := strings.ToLower(fmt.Sprintf("%s-%s-%d", machineName, reqName, idx))
	base = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-':
			return r
		default:
			return '-'
		}
	}, base)
	base = strings.Trim(base, "-")
	if base == "" {
		base = "ppdc"
	}
	if len(base) <= 63 {
		return base
	}
	sum := sha1.Sum([]byte(base))
	h := hex.EncodeToString(sum[:])[:12]
	prefix := base
	if len(prefix) > 50 {
		prefix = prefix[:50]
		prefix = strings.Trim(prefix, "-")
	}
	name := prefix + "-" + h
	if len(name) > 63 {
		name = name[:63]
		name = strings.Trim(name, "-")
	}
	return name
}

func (r *ProxmoxMachineReconciler) getInfraCluster(ctx context.Context, logger *logr.Logger, cluster *clusterv1.Cluster, proxmoxMachine *infrav1alpha1.ProxmoxMachine) (*scope.ClusterScope, error) {
	var clusterScope *scope.ClusterScope
	var err error

	proxmoxCluster := &infrav1alpha1.ProxmoxCluster{}

	infraClusterName := client.ObjectKey{
		Namespace: proxmoxMachine.Namespace,
		Name:      cluster.Spec.InfrastructureRef.Name,
	}

	if err := r.Client.Get(ctx, infraClusterName, proxmoxCluster); err != nil {
		// ProxmoxCluster is not ready
		return nil, nil //nolint:nilerr
	}

	// Create the cluster scope
	clusterScope, err = scope.NewClusterScope(scope.ClusterScopeParams{
		Client:         r.Client,
		Logger:         logger,
		Cluster:        cluster,
		ProxmoxCluster: proxmoxCluster,
		ControllerName: "proxmoxmachine",
		ProxmoxClient:  r.ProxmoxClient,
		IPAMHelper:     ipam.NewHelper(r.Client, proxmoxCluster),
	})
	if err != nil {
		return nil, err
	}

	return clusterScope, nil
}
