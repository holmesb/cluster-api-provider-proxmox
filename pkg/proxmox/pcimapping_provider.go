package proxmox

import (
	"context"
	"fmt"
	"strings"
)

// PCIMapping is a flattened view of a single node/path entry for a PCI hardware mapping.
// One Proxmox hardware mapping can have multiple node/path entries (maps).
//
// ID is the mapping ID (the Proxmox hardware mapping identifier).
// ProxmoxNode and PCIPath come from the individual map entry.
// Description is the mapping comment (used as a semicolon-delimited key=value list).
type PCIMapping struct {
	ID          string
	ProxmoxNode string
	PCIPath     string
	Description string
}

// PCIMappingLister is the minimal interface the claim controller needs.
//
// The implementation should query Proxmox for PCI hardware mappings (equivalent to:
// pvesh get /cluster/mapping/pci --output-format json).
type PCIMappingLister interface {
	ListPCIMappings(ctx context.Context, clusterName string) ([]PCIMapping, error)
}

// APICaller is a tiny abstraction over the Proxmox API client.
//
// It is intentionally minimal so we can adapt whatever client implementation CAPMOX
// is using without importing controller packages.
type APICaller interface {
	Get(ctx context.Context, path string, out any) error
}

// PCIMappingProvider implements PCIMappingLister using the Proxmox API.
type PCIMappingProvider struct {
	API APICaller
}

// pvePCIMappingList is the shape returned by /cluster/mapping/pci.
// The field names reflect typical Proxmox API JSON.
type pvePCIMappingList []pvePCIMapping

type pvePCIMapping struct {
	ID          string   `json:"id"`
	Description string   `json:"description,omitempty"`
	Maps        []string `json:"map,omitempty"`
}

func parsePveMapEntry(s string) (node, path string) {
	// Example: "node=host02,path=0000:01:00,id=10de:1234,subsystem-id=10de:12a3,iommugroup=14"
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "node":
			node = v
		case "path":
			path = v
		}
	}
	return node, path
}

func (p *PCIMappingProvider) ListPCIMappings(ctx context.Context, _ string) ([]PCIMapping, error) {
	if p == nil || p.API == nil {
		return nil, fmt.Errorf("proxmox api client is nil")
	}
	var resp pvePCIMappingList
	if err := p.API.Get(ctx, "/cluster/mapping/pci", &resp); err != nil {
		return nil, err
	}
	out := make([]PCIMapping, 0, len(resp))
	for _, m := range resp {
		if m.ID == "" {
			continue
		}
		for _, raw := range m.Maps {
			node, path := parsePveMapEntry(raw)
			if node == "" || path == "" {
				continue
			}
			out = append(out, PCIMapping{
				ID:          m.ID,
				ProxmoxNode: node,
				PCIPath:     path,
				Description: m.Description,
			})
		}
	}
	return out, nil
}
