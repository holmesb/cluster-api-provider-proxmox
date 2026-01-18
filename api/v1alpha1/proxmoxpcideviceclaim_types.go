// File: api/v1alpha1/proxmoxpcideviceclaim_types.go

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
)

// ProxmoxPCIDeviceClaimSpec defines the desired state of ProxmoxPCIDeviceClaim.
type ProxmoxPCIDeviceClaimSpec struct {
	// ClusterName is the name of the Cluster this claim belongs to.
	//
	// +kubebuilder:validation:MinLength=1
	ClusterName string `json:"clusterName"`

	// Selector is used to match a Proxmox PCI Resource Mapping.
	//
	// The controller interprets this as a Kubernetes LabelSelector applied to a
	// label-set derived from the mapping description (e.g. class=gpu, model_key=10de:1234).
	//
	// +kubebuilder:validation:Required
	Selector metav1.LabelSelector `json:"selector"`

	// ConsumerRef identifies the object which is requesting/owning this claim.
	// Typically this will be a CAPI Machine or an Infrastructure Machine.
	//
	// +optional
	ConsumerRef *corev1.ObjectReference `json:"consumerRef,omitempty"`

	// PreferredProxmoxNode, if set, restricts binding to mappings on that Proxmox node.
	//
	// +optional
	PreferredProxmoxNode string `json:"preferredProxmoxNode,omitempty"`
}

// ProxmoxPCIDeviceClaimPhase is a high-level state indicator for a claim.
type ProxmoxPCIDeviceClaimPhase string

const (
	ProxmoxPCIDeviceClaimPhasePending  ProxmoxPCIDeviceClaimPhase = "Pending"
	ProxmoxPCIDeviceClaimPhaseBound    ProxmoxPCIDeviceClaimPhase = "Bound"
	ProxmoxPCIDeviceClaimPhaseReleased ProxmoxPCIDeviceClaimPhase = "Released"
	ProxmoxPCIDeviceClaimPhaseFailed   ProxmoxPCIDeviceClaimPhase = "Failed"
)

// ProxmoxPCIDeviceClaimStatus defines the observed state of ProxmoxPCIDeviceClaim.
type ProxmoxPCIDeviceClaimStatus struct {
	// Phase is a coarse-grained view of claim lifecycle.
	//
	// +kubebuilder:validation:Enum=Pending;Bound;Released;Failed
	// +optional
	Phase ProxmoxPCIDeviceClaimPhase `json:"phase,omitempty"`

	// BoundMappingID is the Proxmox PCI Resource Mapping ID that has been allocated to this claim.
	//
	// +optional
	BoundMappingID string `json:"boundMappingID,omitempty"`

	// ProxmoxNode is the Proxmox node on which the mapping resides.
	//
	// +optional
	ProxmoxNode string `json:"proxmoxNode,omitempty"`

	// MappingPCIPath is the physical PCI path (function-stripped, e.g. "0000:01:00") associated with the mapping.
	// This is informational and not used as a selector.
	//
	// +optional
	MappingPCIPath string `json:"mappingPCIPath,omitempty"`

	// MappingDescription is a copy of the mapping description at bind time.
	// This is informational and helps debugging.
	//
	// +optional
	MappingDescription string `json:"mappingDescription,omitempty"`

	// ObservedGeneration is the latest generation observed by the controller.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// LastBindTime is when the mapping was last successfully bound.
	//
	// +optional
	LastBindTime *metav1.Time `json:"lastBindTime,omitempty"`

	// Conditions defines current service state of the claim.
	//
	// +optional
	Conditions clusterv1.Conditions `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=cluster-api,scope=Namespaced,shortName=ppdc
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`,description="Claim phase"
// +kubebuilder:printcolumn:name="Mapping",type=string,JSONPath=`.status.boundMappingID`,description="Bound Proxmox mapping ID"
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.status.proxmoxNode`,description="Proxmox node"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ProxmoxPCIDeviceClaim is the Schema for the proxmoxpcideviceclaims API.
type ProxmoxPCIDeviceClaim struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ProxmoxPCIDeviceClaimSpec   `json:"spec,omitempty"`
	Status ProxmoxPCIDeviceClaimStatus `json:"status,omitempty"`
}

// GetConditions returns the list of conditions for this object.
func (r *ProxmoxPCIDeviceClaim) GetConditions() clusterv1.Conditions {
	return r.Status.Conditions
}

// SetConditions sets the conditions on this object.
func (r *ProxmoxPCIDeviceClaim) SetConditions(conditions clusterv1.Conditions) {
	r.Status.Conditions = conditions
}

// +kubebuilder:object:root=true

// ProxmoxPCIDeviceClaimList contains a list of ProxmoxPCIDeviceClaim.
type ProxmoxPCIDeviceClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ProxmoxPCIDeviceClaim `json:"items"`
}
