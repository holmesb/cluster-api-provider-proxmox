/*
Copyright 2023 IONOS Cloud.

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

package proxmox

import "github.com/luthermonson/go-proxmox"

// VMCloneRequest Is the object used to clone a VM.
type VMCloneRequest struct {
	Node        string `json:"node"`
	NewID       int    `json:"newID"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Format      string `json:"format,omitempty"`
	Full        uint8  `json:"full,omitempty"`
	Pool        string `json:"pool,omitempty"`
	SnapName    string `json:"snapname,omitempty"`
	Storage     string `json:"storage,omitempty"`
	Target      string `json:"target,omitempty"`
}

// VMCloneResponse response returned when cloning a VM.
type VMCloneResponse struct {
	NewID int64         `json:"newId,omitempty"`
	Task  *proxmox.Task `json:"task,omitempty"`
}

// VirtualMachineOption is an alias for VirtualMachineOption to prevent import conflicts.
type VirtualMachineOption = proxmox.VirtualMachineOption

// StorageStatus represents the current status of a Proxmox storage on a node.
// It is a simplified view used by the scheduler and higher-level logic.
type StorageStatus struct {
	Node         string // node name
	Name         string // storage ID / name
	Enabled      bool
	UsedFraction float64
	Active       bool
	Content      string
	Shared       bool
	Avail        uint64
	Type         string
	Used         uint64
	Total        uint64

	// VirtualAllocated is the sum of provisioned sizes (in bytes) for all
	// volumes on this storage, derived from the storage content API.
	VirtualAllocated uint64

	// VirtualAvail is the remaining capacity (in bytes) based on provisioned
	// sizes: Total - VirtualAllocated. Scheduler and higher-level logic should
	// use this field instead of Avail when comparing storages.
	VirtualAvail uint64
}
