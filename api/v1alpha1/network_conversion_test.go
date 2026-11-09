/*
Copyright 2026 IONOS Cloud.

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

package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/ionos-cloud/cluster-api-provider-proxmox/api/v1alpha2"
)

func TestNetworkFamilyConversionRoundTrip(t *testing.T) {
	for _, family := range []struct {
		name string
		is6  *bool
	}{
		{name: "unspecified"},
		{name: "IPv4", is6: ptr.To(false)},
		{name: "IPv6", is6: ptr.To(true)},
	} {
		t.Run(family.name, func(t *testing.T) {
			target := "192.0.2.0/24"
			if ptr.Deref(family.is6, false) {
				target = "2001:db8::/64"
			}
			routing := v1alpha2.Routing{
				Routes: []v1alpha2.RouteSpec{{To: ptr.To(target), Is6: family.is6}},
				RoutingPolicy: []v1alpha2.RoutingPolicySpec{{
					From: ptr.To(target), Table: ptr.To[int32](100), Is6: family.is6,
				}},
			}
			spec := v1alpha2.ProxmoxMachineSpec{Network: &v1alpha2.NetworkSpec{
				NetworkDevices: []v1alpha2.NetworkDevice{
					{Name: "net0", Bridge: ptr.To("vmbr0")},
					{Name: "net1", Bridge: ptr.To("vmbr1"), InterfaceConfig: v1alpha2.InterfaceConfig{
						Routing: routing,
					}},
				},
				VirtualNetworkDevices: v1alpha2.VirtualNetworkDevices{VRFs: []v1alpha2.VRFDevice{{
					Name: "blue", Table: 100, Interfaces: []v1alpha2.NetName{"net1"}, Routing: routing,
				}}},
			}}

			t.Run("machine", func(t *testing.T) {
				hub := &v1alpha2.ProxmoxMachine{Spec: *spec.DeepCopy()}
				spoke, restored := &ProxmoxMachine{}, &v1alpha2.ProxmoxMachine{}
				require.NoError(t, spoke.ConvertFrom(hub))
				require.NoError(t, spoke.ConvertTo(restored))
				require.Len(t, restored.Spec.Network.NetworkDevices, 2)
				require.Equal(t, routing, restored.Spec.Network.NetworkDevices[1].Routing)
				require.Len(t, restored.Spec.Network.VRFs, 1)
				require.Equal(t, routing, restored.Spec.Network.VRFs[0].Routing)
			})

			t.Run("template", func(t *testing.T) {
				hub := &v1alpha2.ProxmoxMachineTemplate{}
				hub.Spec.Template.Spec = *spec.DeepCopy()
				spoke, restored := &ProxmoxMachineTemplate{}, &v1alpha2.ProxmoxMachineTemplate{}
				require.NoError(t, spoke.ConvertFrom(hub))
				require.NoError(t, spoke.ConvertTo(restored))
				require.Len(t, restored.Spec.Template.Spec.Network.NetworkDevices, 2)
				require.Equal(t, routing, restored.Spec.Template.Spec.Network.NetworkDevices[1].Routing)
				require.Len(t, restored.Spec.Template.Spec.Network.VRFs, 1)
				require.Equal(t, routing, restored.Spec.Template.Spec.Network.VRFs[0].Routing)
			})
		})
	}
}
