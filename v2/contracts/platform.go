package contracts

import "time"

// C57 — снимок платформы (contracts/c57-platform.schema.json): отправляет collector, подпись — его ключом с
// префиксом PlatformSignaturePrefix. Отдельно от C03.

const PlatformSignaturePrefix = "SURVEYSCAN-PLATFORM-V1\n"

type PlatformObject struct {
	Ref      string         `json:"ref"`
	Kind     string         `json:"kind"`
	Name     string         `json:"name"`
	BiosUUID *string        `json:"bios_uuid"`
	Serial   *string        `json:"serial"`
	Hostname *string        `json:"hostname"`
	MACs     []string       `json:"macs"`
	Attrs    map[string]any `json:"attrs"`
}

type PlatformRelation struct {
	From string `json:"from"`
	Type string `json:"type"`
	To   string `json:"to"`
}

type PlatformSnapshot struct {
	Major        int                `json:"major"`
	SnapshotID   string             `json:"snapshot_id"`
	Tenant       string             `json:"tenant_id"`
	Source       string             `json:"source_id"`
	Generation   string             `json:"generation_id"`
	Target       *string            `json:"target_id"`
	Platform     string             `json:"platform"`
	Instance     string             `json:"instance"`
	InstanceName string             `json:"instance_name"`
	CollectedAt  time.Time          `json:"collected_at"`
	Complete     bool               `json:"complete"`
	Objects      []PlatformObject   `json:"objects"`
	Relations    []PlatformRelation `json:"relations"`
	Errors       []string           `json:"errors"`
}
