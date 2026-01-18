/*
--- File: internal/controller/proxmoxpcideviceclaim_controller_test.go ---
*/

package controller

import (
	"context"
	"regexp"
	"testing"

	infrav1 "github.com/ionos-cloud/cluster-api-provider-proxmox/api/v1alpha1"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestParseSemicolonKV(t *testing.T) {
	got := parseSemicolonKV("class=gpu;model_key=10de:1234; chip=ExampleChip ;empty=;bad;=noval")
	if got["class"] != "gpu" {
		t.Fatalf("expected class=gpu, got %q", got["class"])
	}
	if got["model_key"] != "10de:1234" {
		t.Fatalf("expected model_key=10de:1234, got %q", got["model_key"])
	}
	if _, ok := got["bad"]; ok {
		t.Fatalf("did not expect key 'bad' to be parsed")
	}
	if _, ok := got[""]; ok {
		t.Fatalf("did not expect empty key to be parsed")
	}

	// Key casing in the description should not matter.
	got2 := parseSemicolonKV("CLASS=gpu;MODEL_KEY=10DE:1234")
	if got2["class"] != "gpu" {
		t.Fatalf("expected class=gpu, got %q", got2["class"])
	}
	if got2["model_key"] != "10de:1234" {
		t.Fatalf("expected model_key=10de:1234, got %q", got2["model_key"])
	}
}

func TestSelectorMatches_ModelKeyIsCaseInsensitive(t *testing.T) {
	lbls := parseSemicolonKV("class=gpu;model_key=10DE:1234")

	// matchLabels with lower-case value
	sel := &metav1.LabelSelector{MatchLabels: map[string]string{"class": "gpu", "model_key": "10de:1234"}}
	if !selectorMatches(sel, lbls) {
		t.Fatalf("expected selector to match labels (case-insensitive model_key)")
	}

	// matchExpressions IN with mixed case values
	sel2 := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "model_key", Operator: metav1.LabelSelectorOpIn, Values: []string{"10de:1234"}}}}
	if !selectorMatches(sel2, lbls) {
		t.Fatalf("expected selector (In) to match labels (case-insensitive model_key)")
	}

	// NotIn should also be case-insensitive
	sel3 := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "model_key", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"10DE:1234"}}}}
	if selectorMatches(sel3, lbls) {
		t.Fatalf("expected selector (NotIn) to not match labels (case-insensitive model_key)")
	}
}

func TestLeaseNameForMappingID_IsDNS1123AndShortEnough(t *testing.T) {
	name := leaseNameForMappingID("gpu_10de_1234_host04_01_00")
	if len(name) > 63 {
		t.Fatalf("expected <=63 chars, got %d: %q", len(name), name)
	}
	// DNS-1123 label: lowercase alphanumeric or '-', must start/end alphanumeric.
	re := regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	if !re.MatchString(name) {
		t.Fatalf("expected DNS-1123 label, got %q", name)
	}
}

func TestTryAcquireLease_IsAtomic(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := infrav1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(infrav1): %v", err)
	}
	if err := coordinationv1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme(coordinationv1): %v", err)
	}

	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	claim := &infrav1.ProxmoxPCIDeviceClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "c1",
			Namespace: "default",
			UID:       types.UID("uid-1"),
		},
		Spec: infrav1.ProxmoxPCIDeviceClaimSpec{ClusterName: "cluster"},
	}
	if err := c.Create(context.Background(), claim); err != nil {
		t.Fatalf("create claim: %v", err)
	}

	r := &ProxmoxPCIDeviceClaimReconciler{Client: c, Scheme: scheme}

	ok1, leaseName, err := r.tryAcquireLease(context.Background(), claim, "gpu_10de_1234_host04_01_00")
	if err != nil {
		t.Fatalf("tryAcquireLease 1: %v", err)
	}
	if !ok1 {
		t.Fatalf("expected first lease acquisition to succeed")
	}

	// Second attempt for same mapping ID must fail (AlreadyExists -> ok=false).
	ok2, leaseName2, err := r.tryAcquireLease(context.Background(), claim, "gpu_10de_1234_host04_01_00")
	if err != nil {
		t.Fatalf("tryAcquireLease 2: %v", err)
	}
	if ok2 {
		t.Fatalf("expected second lease acquisition to fail")
	}
	if leaseName2 != leaseName {
		t.Fatalf("expected same lease name, got %q vs %q", leaseName2, leaseName)
	}

	// Ensure the lease object actually exists.
	lease := &coordinationv1.Lease{}
	if err := c.Get(context.Background(), ctrlclient.ObjectKey{Name: leaseName, Namespace: "default"}, lease); err != nil {
		t.Fatalf("expected lease to exist: %v", err)
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != string(claim.UID) {
		t.Fatalf("expected holder identity to be claim UID, got %#v", lease.Spec.HolderIdentity)
	}
}
