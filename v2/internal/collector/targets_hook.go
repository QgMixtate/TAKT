package collector

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/QgMixtate/surveyscan/v2/contracts"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/wire"
)

// TargetSync — крючок целей удалённого сбора (C51.03, пакет collecttargets): задаётся при запуске collector.
// Связь через крючок, а не импорт: пакет агента в тестах сам импортирует collector.
func (c *Collector) syncTargets(run, task context.Context) error {
	if c.TargetSync == nil {
		return nil
	}
	return c.TargetSync(run, task)
}

// MachinePost — запрос к центру по mTLS личности collector (для крючков вроде collecttargets).
func (c *Collector) MachinePost(ctx context.Context, path string, raw []byte) (int, []byte, error) {
	return c.post(ctx, path, raw, "")
}

// SubmitPlatform — C57: подписывает снимок платформы ключом collector (личность — его) и отправляет центру.
func (c *Collector) SubmitPlatform(ctx context.Context, s contracts.PlatformSnapshot) error {
	if c.signing == nil {
		return errors.New("collector signing key unavailable")
	}
	s.Major, s.SnapshotID = 1, identifier.New()
	s.Tenant, s.Source, s.Generation = c.Claims.Tenant, c.Claims.Source, c.Claims.Generation
	payload, e := json.Marshal(s)
	if e != nil {
		return e
	}
	canonical, e := wire.Canonical(payload)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(canonical)
	signature := ed25519.Sign(c.signing, append([]byte(contracts.PlatformSignaturePrefix), canonical...))
	body, _ := json.Marshal(map[string]any{"payload": json.RawMessage(payload), "payload_sha256": hex.EncodeToString(sum[:]), "key_id": c.Claims.KeyID, "signature": base64.RawURLEncoding.EncodeToString(signature)})
	code, _, e := c.post(ctx, "/api/v1/machine/platform-snapshots", body, "")
	if e != nil {
		return e
	}
	if code != 200 {
		return errors.New("platform snapshot not accepted")
	}
	return nil
}
