package assets

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/jackc/pgx/v5"
)

// Retirement — вывод актива из учёта (C42, частично): когда, кто и почему.
type Retirement struct {
	At     time.Time `json:"retired_at"`
	Reason string    `json:"reason"`
	By     string    `json:"retired_by"`
}

// Retirement — сведения о выводе или nil, если актив в учёте.
func (Store) Retirement(ctx context.Context, tx pgx.Tx, tenant, asset string) (*Retirement, error) {
	var at *time.Time
	var reason, by *string
	e := tx.QueryRow(ctx, "SELECT retired_at,retired_reason,retired_by::text FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2", tenant, asset).Scan(&at, &reason, &by)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, domain.NotFound
	}
	if e != nil || at == nil {
		return nil, e
	}
	return &Retirement{At: at.UTC(), Reason: *reason, By: *by}, nil
}

// Retire выводит актив из учёта. Объединённый — NotFound (работать с итоговым); уже выведенный — Conflict.
func (Store) Retire(ctx context.Context, tx pgx.Tx, tenant, asset, reason, actor string) error {
	reason = strings.TrimSpace(reason)
	if n := utf8.RuneCountInString(reason); n < 1 || n > 500 || !utf8.ValidString(reason) {
		return domain.Invalid
	}
	tag, e := tx.Exec(ctx, `UPDATE assets.assets SET retired_at=now(),retired_reason=$3,retired_by=$4,lifecycle_state='retired'
WHERE tenant_id=$1 AND asset_uid=$2 AND merged_into IS NULL AND retired_at IS NULL`, tenant, asset, reason, actor)
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	return stateConflict(ctx, tx, tenant, asset)
}

// Restore возвращает актив в учёт; не выведенный — Conflict.
func (Store) Restore(ctx context.Context, tx pgx.Tx, tenant, asset string) error {
	tag, e := tx.Exec(ctx, `UPDATE assets.assets SET retired_at=NULL,retired_reason=NULL,retired_by=NULL,lifecycle_state='unknown'
WHERE tenant_id=$1 AND asset_uid=$2 AND merged_into IS NULL AND retired_at IS NOT NULL`, tenant, asset)
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	return stateConflict(ctx, tx, tenant, asset)
}

func stateConflict(ctx context.Context, tx pgx.Tx, tenant, asset string) error {
	var merged bool
	e := tx.QueryRow(ctx, "SELECT merged_into IS NOT NULL FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2", tenant, asset).Scan(&merged)
	if errors.Is(e, pgx.ErrNoRows) || e == nil && merged {
		return domain.NotFound
	}
	if e != nil {
		return e
	}
	return domain.Conflict
}

// RetiredIDs — выведенные из учёта активы, новые сверху (не больше limit).
func (Store) RetiredIDs(ctx context.Context, tx pgx.Tx, tenant string, limit int) ([]string, error) {
	rows, e := tx.Query(ctx, "SELECT asset_uid::text FROM assets.assets WHERE tenant_id=$1 AND merged_into IS NULL AND retired_at IS NOT NULL ORDER BY retired_at DESC, asset_uid LIMIT $2", tenant, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
