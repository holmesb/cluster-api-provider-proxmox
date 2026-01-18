// File: internal/controller/proxmoxpcideviceclaim_controller.go

package controller

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	infrav1 "github.com/ionos-cloud/cluster-api-provider-proxmox/api/v1alpha1"
	"github.com/ionos-cloud/cluster-api-provider-proxmox/pkg/proxmox"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/cluster-api/util/conditions"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	proxmoxPCIDeviceClaimFinalizer = "proxmoxpcideviceclaim.infrastructure.cluster.x-k8s.io/finalizer"
	conditionReady                 = "Ready"
	leaseNamePrefix                = "ppdc-" // Proxmox PCI Device Claim
)

// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=proxmoxpcideviceclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=proxmoxpcideviceclaims/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=infrastructure.cluster.x-k8s.io,resources=proxmoxpcideviceclaims/finalizers,verbs=update
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete

// ProxmoxPCIDeviceClaimReconciler reconciles a ProxmoxPCIDeviceClaim object.
type ProxmoxPCIDeviceClaimReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	Recorder        record.EventRecorder
	MappingProvider proxmox.PCIMappingLister
}

func (r *ProxmoxPCIDeviceClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("proxmoxpcideviceclaim", req.NamespacedName)

	var claim infrav1.ProxmoxPCIDeviceClaim
	if err := r.Get(ctx, req.NamespacedName, &claim); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	claim.Status.ObservedGeneration = claim.GetGeneration()

	// Handle deletion.
	if !claim.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &claim)
	}

	// Ensure finalizer.
	if !controllerutil.ContainsFinalizer(&claim, proxmoxPCIDeviceClaimFinalizer) {
		controllerutil.AddFinalizer(&claim, proxmoxPCIDeviceClaimFinalizer)
		if err := r.Update(ctx, &claim); err != nil {
			return ctrl.Result{}, err
		}
		// Requeue so we continue with a fresh object.
		return ctrl.Result{Requeue: true}, nil
	}

	// Already bound: ensure status is consistent.
	if claim.Status.BoundMappingID != "" {
		if claim.Status.Phase != infrav1.ProxmoxPCIDeviceClaimPhaseBound {
			claim.Status.Phase = infrav1.ProxmoxPCIDeviceClaimPhaseBound
		}
		conditions.MarkTrue(&claim, conditionReady)
		if err := r.Status().Update(ctx, &claim); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// Not bound: attempt to bind.
	if r.MappingProvider == nil {
		claim.Status.Phase = infrav1.ProxmoxPCIDeviceClaimPhaseFailed
		conditions.MarkFalse(&claim, conditionReady, "NoProvider", clusterv1.ConditionSeverityWarning, "no mapping provider configured")
		_ = r.Status().Update(ctx, &claim)
		logger.Info("no mapping provider configured")
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	mappings, err := r.MappingProvider.ListPCIMappings(ctx, claim.Spec.ClusterName)
	if err != nil {
		claim.Status.Phase = infrav1.ProxmoxPCIDeviceClaimPhaseFailed
		conditions.MarkFalse(&claim, conditionReady, "ListFailed", clusterv1.ConditionSeverityWarning, "%s", err.Error())
		_ = r.Status().Update(ctx, &claim)
		return ctrl.Result{RequeueAfter: 15 * time.Second}, err
	}

	candidates := make([]proxmox.PCIMapping, 0, len(mappings))
	for _, m := range mappings {
		if claim.Spec.PreferredProxmoxNode != "" && m.ProxmoxNode != claim.Spec.PreferredProxmoxNode {
			continue
		}
		if m.ID == "" {
			continue
		}

		lbls := parseSemicolonKV(m.Description)
		if selectorMatches(&claim.Spec.Selector, lbls) {
			candidates = append(candidates, m)
		}
	}

	if len(candidates) == 0 {
		claim.Status.Phase = infrav1.ProxmoxPCIDeviceClaimPhasePending
		conditions.MarkFalse(&claim, conditionReady, "NoMatchingMapping", clusterv1.ConditionSeverityInfo, "no mapping matched selector")
		_ = r.Status().Update(ctx, &claim)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Stable ordering, so multiple contenders try leases in the same order.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })

	var chosen *proxmox.PCIMapping
	for i := range candidates {
		m := &candidates[i]
		ok, leaseName, leaseErr := r.tryAcquireLease(ctx, &claim, m.ID)
		if leaseErr != nil {
			claim.Status.Phase = infrav1.ProxmoxPCIDeviceClaimPhaseFailed
			conditions.MarkFalse(&claim, conditionReady, "LeaseError", clusterv1.ConditionSeverityWarning, "%s", leaseErr.Error())
			_ = r.Status().Update(ctx, &claim)
			return ctrl.Result{RequeueAfter: 15 * time.Second}, leaseErr
		}
		if ok {
			chosen = m
			logger.Info("acquired lease", "lease", leaseName, "mappingID", m.ID)
			break
		}
	}

	if chosen == nil {
		claim.Status.Phase = infrav1.ProxmoxPCIDeviceClaimPhasePending
		conditions.MarkFalse(&claim, conditionReady, "NoAvailableMapping", clusterv1.ConditionSeverityInfo, "no free mapping matched selector")
		_ = r.Status().Update(ctx, &claim)
		return ctrl.Result{RequeueAfter: 20 * time.Second}, nil
	}

	claim.Status.BoundMappingID = chosen.ID
	claim.Status.ProxmoxNode = chosen.ProxmoxNode
	claim.Status.MappingPCIPath = chosen.PCIPath
	claim.Status.MappingDescription = chosen.Description
	now := metav1.Now()
	claim.Status.LastBindTime = &now
	claim.Status.Phase = infrav1.ProxmoxPCIDeviceClaimPhaseBound
	conditions.MarkTrue(&claim, conditionReady)

	if err := r.Status().Update(ctx, &claim); err != nil {
		return ctrl.Result{}, err
	}

	r.Recorder.Eventf(&claim, corev1.EventTypeNormal, "Bound", "Bound to mapping %q on node %q", chosen.ID, chosen.ProxmoxNode)
	logger.Info("bound claim", "mappingID", chosen.ID, "node", chosen.ProxmoxNode)

	return ctrl.Result{}, nil
}

func (r *ProxmoxPCIDeviceClaimReconciler) reconcileDelete(ctx context.Context, claim *infrav1.ProxmoxPCIDeviceClaim) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(claim, proxmoxPCIDeviceClaimFinalizer) {
		return ctrl.Result{}, nil
	}

	// Best-effort: release the lease first (otherwise it should be GC'd via ownerRef).
	if claim.Status.BoundMappingID != "" {
		leaseName := leaseNameForMappingID(claim.Status.BoundMappingID)
		lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: leaseName, Namespace: claim.Namespace}}
		err := r.Delete(ctx, lease)
		if err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
	}

	claim.Status.Phase = infrav1.ProxmoxPCIDeviceClaimPhaseReleased
	conditions.MarkFalse(claim, conditionReady, "Deleting", clusterv1.ConditionSeverityInfo, "claim is being deleted")
	_ = r.Status().Update(ctx, claim)

	controllerutil.RemoveFinalizer(claim, proxmoxPCIDeviceClaimFinalizer)
	if err := r.Update(ctx, claim); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *ProxmoxPCIDeviceClaimReconciler) tryAcquireLease(ctx context.Context, claim *infrav1.ProxmoxPCIDeviceClaim, mappingID string) (bool, string, error) {
	leaseName := leaseNameForMappingID(mappingID)

	now := metav1.NowMicro()
	holder := string(claim.UID)
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Name:      leaseName,
			Namespace: claim.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: infrav1.GroupVersion.String(),
					Kind:       "ProxmoxPCIDeviceClaim",
					Name:       claim.Name,
					UID:        claim.UID,
				},
			},
		},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       &holder,
			AcquireTime:          &now,
			RenewTime:            &now,
			LeaseDurationSeconds: int32Ptr(120),
		},
	}

	if err := r.Create(ctx, lease); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return false, leaseName, nil
		}
		return false, leaseName, err
	}
	return true, leaseName, nil
}

func leaseNameForMappingID(mappingID string) string {
	// Lease names must be DNS-1123 labels.
	// Mapping IDs may contain underscores or other characters.
	base := strings.ToLower(mappingID)
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
		base = "mapping"
	}

	name := leaseNamePrefix + base
	if len(name) <= 63 {
		return name
	}

	// Too long: keep a short prefix and add a stable hash suffix.
	sum := sha1.Sum([]byte(mappingID))
	h := hex.EncodeToString(sum[:])[:12]
	prefix := leaseNamePrefix + base
	if len(prefix) > 50 {
		prefix = prefix[:50]
		prefix = strings.Trim(prefix, "-")
	}
	name = prefix + "-" + h
	if len(name) > 63 {
		name = name[:63]
		name = strings.Trim(name, "-")
	}
	return name
}

func int32Ptr(v int32) *int32 { return &v }

// parseSemicolonKV parses "k=v;k2=v2" into a map.
// Keys which are empty are ignored; values may be empty.
func parseSemicolonKV(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if !ok || k == "" {
			continue
		}
		// Normalise well-known keys where case-insensitive matching is desired.
		if k == "model_key" {
			v = strings.ToLower(v)
		}
		out[k] = v
	}
	return out
}

func selectorMatches(sel *metav1.LabelSelector, lbls map[string]string) bool {
	if sel == nil {
		return true
	}

	// matchLabels (exact match)
	for k, v := range sel.MatchLabels {
		k = strings.ToLower(k)
		if k == "model_key" {
			v = strings.ToLower(v)
		}
		if lbls[k] != v {
			return false
		}
	}

	// matchExpressions
	for _, req := range sel.MatchExpressions {
		key := strings.ToLower(req.Key)
		val, exists := lbls[key]

		values := req.Values
		if key == "model_key" {
			val = strings.ToLower(val)
			if len(values) > 0 {
				values = make([]string, 0, len(req.Values))
				for _, w := range req.Values {
					values = append(values, strings.ToLower(w))
				}
			}
		}

		switch req.Operator {
		case metav1.LabelSelectorOpIn:
			ok := false
			for _, want := range values {
				if val == want {
					ok = true
					break
				}
			}
			if !ok {
				return false
			}
		case metav1.LabelSelectorOpNotIn:
			for _, bad := range values {
				if val == bad {
					return false
				}
			}
		case metav1.LabelSelectorOpExists:
			if !exists {
				return false
			}
		case metav1.LabelSelectorOpDoesNotExist:
			if exists {
				return false
			}
		default:
			// Unknown operator
			return false
		}
	}

	return true
}

func (r *ProxmoxPCIDeviceClaimReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&infrav1.ProxmoxPCIDeviceClaim{}).
		Complete(r)
}
