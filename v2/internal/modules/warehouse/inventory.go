package warehouse

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

// Инвентаризация места (C45.01, AC W2-06): снимок учёта на начало → ввод факта → расхождения → закрытие актом с
// корректирующими движениями «недостача» (from_location) и «излишек» (to_location). Журнал и остатки сходятся:
// корректировки — обычные записи журнала вида adjust.

type Inventory struct {
	ID        string     `json:"inventory_id"`
	Location  string     `json:"location_id"`
	ActNo     string     `json:"act_no"`
	Basis     string     `json:"basis"`
	State     string     `json:"state"`
	StartedAt time.Time  `json:"started_at"`
	StartedBy string     `json:"started_by"`
	ClosedAt  *time.Time `json:"closed_at"`
	Shortage  *string    `json:"shortage_movement"`
	Surplus   *string    `json:"surplus_movement"`
}

// InventoryLine — строка сверки: серийный экземпляр (по учёту / найден) или количество позиции.
type InventoryLine struct {
	Item     string   `json:"item_id"`
	ItemName string   `json:"item_name"`
	Unit     string   `json:"unit"`
	UnitID   *string  `json:"unit_id"`
	Serial   *string  `json:"serial"`
	Expected float64  `json:"expected"`
	Counted  *float64 `json:"counted"` // nil — не вводилось
	Result   string   `json:"result"`  // ok | shortage | surplus | elsewhere
	Where    *string  `json:"where"`   // для elsewhere: где числится найденный экземпляр
}

type InventoryDetail struct {
	Inventory
	Lines []InventoryLine `json:"lines"`
}

// Count — ввод факта: найденные серийные номера и посчитанные количества (заменяет предыдущий ввод целиком).
type Count struct {
	Serials []struct {
		Item   string `json:"item_id"`
		Serial string `json:"serial"`
	} `json:"serials"`
	Quantities []struct {
		Item     string  `json:"item_id"`
		Quantity float64 `json:"quantity"`
	} `json:"quantities"`
}

func nextAct(ctx context.Context, tx pgx.Tx, tenant string, at time.Time) (string, error) {
	var no int
	e := tx.QueryRow(ctx, `INSERT INTO warehouse.act_counters(tenant_id,year,last) VALUES($1,$2,1)
ON CONFLICT (tenant_id,year) DO UPDATE SET last=warehouse.act_counters.last+1 RETURNING last`, tenant, at.Year()).Scan(&no)
	return fmt.Sprintf("%d-%06d", at.Year(), no), e
}

// StartInventory открывает инвентаризацию склада/ячейки и снимает учёт на начало. Одна открытая на место.
func (s Store) StartInventory(ctx context.Context, tx pgx.Tx, tenant, actor, location, basis string) (InventoryDetail, error) {
	basis = strings.TrimSpace(basis)
	if !identifier.Valid(location) || !text(basis, 1, 256) {
		return InventoryDetail{}, domain.Invalid
	}
	if kind, e := locationKind(ctx, tx, tenant, location); e != nil || (kind != "warehouse" && kind != "bin") {
		return InventoryDetail{}, orInvalid(e)
	}
	id := identifier.New()
	var at time.Time
	if e := tx.QueryRow(ctx, "SELECT now()").Scan(&at); e != nil {
		return InventoryDetail{}, e
	}
	act, e := nextAct(ctx, tx, tenant, at)
	if e != nil {
		return InventoryDetail{}, e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO warehouse.inventories(tenant_id,inventory_id,location_id,act_no,basis,state,started_at,started_by) VALUES($1,$2,$3,$4,$5,'open',$6,$7)", tenant, id, location, act, basis, at, actor); e != nil {
		return InventoryDetail{}, conflict(e) // по месту уже идёт инвентаризация
	}
	// снимок: экземпляры на месте (свободные и в резерве) и остатки
	if _, e = tx.Exec(ctx, `INSERT INTO warehouse.inventory_expected(tenant_id,inventory_id,item_id,unit_id,quantity)
SELECT tenant_id,$2::uuid,item_id,unit_id,1::numeric FROM warehouse.units WHERE tenant_id=$1 AND location_id=$3 AND state IN ('in_stock','reserved')
UNION ALL SELECT tenant_id,$2::uuid,item_id,NULL::uuid,quantity FROM warehouse.stock WHERE tenant_id=$1 AND location_id=$3 AND quantity>0`, tenant, id, location); e != nil {
		return InventoryDetail{}, e
	}
	return s.InventoryDetail(ctx, tx, tenant, id)
}

// SetCount заменяет введённый факт открытой инвентаризации.
func (s Store) SetCount(ctx context.Context, tx pgx.Tx, tenant, id string, c Count) (InventoryDetail, error) {
	if len(c.Serials)+len(c.Quantities) > 5000 {
		return InventoryDetail{}, domain.Invalid
	}
	var state string
	if e := tx.QueryRow(ctx, "SELECT state FROM warehouse.inventories WHERE tenant_id=$1 AND inventory_id=$2 FOR UPDATE", tenant, id).Scan(&state); errors.Is(e, pgx.ErrNoRows) {
		return InventoryDetail{}, domain.NotFound
	} else if e != nil {
		return InventoryDetail{}, e
	}
	if state != "open" {
		return InventoryDetail{}, domain.Conflict
	}
	if _, e := tx.Exec(ctx, "DELETE FROM warehouse.inventory_counts WHERE tenant_id=$1 AND inventory_id=$2", tenant, id); e != nil {
		return InventoryDetail{}, e
	}
	for _, x := range c.Serials {
		serial := strings.TrimSpace(x.Serial)
		if kind, e := itemKind(ctx, tx, tenant, x.Item); e != nil || kind != "serial" || !text(serial, 1, 128) {
			return InventoryDetail{}, orInvalid(e)
		}
		if _, e := tx.Exec(ctx, "INSERT INTO warehouse.inventory_counts(tenant_id,inventory_id,item_id,serial,quantity) VALUES($1,$2,$3,$4,1)", tenant, id, x.Item, serial); e != nil {
			return InventoryDetail{}, conflict(e) // один серийный номер дважды
		}
	}
	for _, x := range c.Quantities {
		if kind, e := itemKind(ctx, tx, tenant, x.Item); e != nil || kind != "quantity" || x.Quantity < 0 || x.Quantity > 1e9 {
			return InventoryDetail{}, orInvalid(e)
		}
		if _, e := tx.Exec(ctx, "INSERT INTO warehouse.inventory_counts(tenant_id,inventory_id,item_id,quantity) VALUES($1,$2,$3,$4)", tenant, id, x.Item, x.Quantity); e != nil {
			return InventoryDetail{}, conflict(e)
		}
	}
	return s.InventoryDetail(ctx, tx, tenant, id)
}

func (Store) inventory(ctx context.Context, tx pgx.Tx, tenant, id string) (Inventory, error) {
	var v Inventory
	if !identifier.Valid(id) {
		return v, domain.NotFound
	}
	e := tx.QueryRow(ctx, `SELECT inventory_id::text,location_id::text,act_no,basis,state,started_at,started_by,closed_at,shortage_movement::text,surplus_movement::text
FROM warehouse.inventories WHERE tenant_id=$1 AND inventory_id=$2`, tenant, id).Scan(&v.ID, &v.Location, &v.ActNo, &v.Basis, &v.State, &v.StartedAt, &v.StartedBy, &v.ClosedAt, &v.Shortage, &v.Surplus)
	if errors.Is(e, pgx.ErrNoRows) {
		return v, domain.NotFound
	}
	return v, e
}

// InventoryDetail — инвентаризация и строки сверки (учёт на начало против факта).
func (s Store) InventoryDetail(ctx context.Context, tx pgx.Tx, tenant, id string) (InventoryDetail, error) {
	v, e := s.inventory(ctx, tx, tenant, id)
	if e != nil {
		return InventoryDetail{}, e
	}
	d := InventoryDetail{Inventory: v, Lines: []InventoryLine{}}
	// серийные: по учёту (найден/не найден) + найденные сверх учёта (на другом месте/у держателя или неизвестные)
	rows, e := tx.Query(ctx, `WITH exp AS (SELECT x.item_id,x.unit_id,u.serial FROM warehouse.inventory_expected x JOIN warehouse.units u ON u.tenant_id=x.tenant_id AND u.unit_id=x.unit_id
  WHERE x.tenant_id=$1 AND x.inventory_id=$2),
 cnt AS (SELECT item_id,serial FROM warehouse.inventory_counts WHERE tenant_id=$1 AND inventory_id=$2 AND serial IS NOT NULL),
 counted AS (SELECT EXISTS(SELECT 1 FROM warehouse.inventory_counts WHERE tenant_id=$1 AND inventory_id=$2) AS has)
SELECT e.item_id::text,i.name,i.unit,e.unit_id::text,e.serial,1::float8,
 CASE WHEN EXISTS(SELECT 1 FROM cnt c WHERE c.item_id=e.item_id AND lower(c.serial)=lower(e.serial)) THEN 1::float8 WHEN (SELECT has FROM counted) THEN 0::float8 END,
 CASE WHEN EXISTS(SELECT 1 FROM cnt c WHERE c.item_id=e.item_id AND lower(c.serial)=lower(e.serial)) THEN 'ok' ELSE 'shortage' END, NULL::text
FROM exp e JOIN warehouse.items i ON i.tenant_id=$1 AND i.item_id=e.item_id
UNION ALL
SELECT c.item_id::text,i.name,i.unit,u.unit_id::text,c.serial,0::float8,1::float8,
 CASE WHEN u.unit_id IS NULL THEN 'surplus' ELSE 'elsewhere' END,
 CASE WHEN u.unit_id IS NULL THEN NULL ELSE u.state||COALESCE(':'||u.location_id::text,'')||COALESCE(':'||u.holder_id::text,'') END
FROM cnt c JOIN warehouse.items i ON i.tenant_id=$1 AND i.item_id=c.item_id
LEFT JOIN warehouse.units u ON u.tenant_id=$1 AND u.item_id=c.item_id AND lower(u.serial)=lower(c.serial)
WHERE NOT EXISTS(SELECT 1 FROM exp e WHERE e.item_id=c.item_id AND lower(e.serial)=lower(c.serial))
UNION ALL
SELECT COALESCE(x.item_id,k.item_id)::text,i.name,i.unit,NULL,NULL,COALESCE(x.quantity,0)::float8,k.quantity::float8,
 CASE WHEN k.quantity IS NULL THEN 'ok' WHEN k.quantity=COALESCE(x.quantity,0) THEN 'ok' WHEN k.quantity<COALESCE(x.quantity,0) THEN 'shortage' ELSE 'surplus' END,NULL
FROM (SELECT item_id,quantity FROM warehouse.inventory_expected WHERE tenant_id=$1 AND inventory_id=$2 AND unit_id IS NULL) x
FULL JOIN (SELECT item_id,quantity FROM warehouse.inventory_counts WHERE tenant_id=$1 AND inventory_id=$2 AND serial IS NULL) k ON k.item_id=x.item_id
JOIN warehouse.items i ON i.tenant_id=$1 AND i.item_id=COALESCE(x.item_id,k.item_id)
ORDER BY 2,5`, tenant, id)
	if e != nil {
		return d, e
	}
	d.Lines, e = pgx.CollectRows(rows, func(r pgx.CollectableRow) (InventoryLine, error) {
		var l InventoryLine
		return l, r.Scan(&l.Item, &l.ItemName, &l.Unit, &l.UnitID, &l.Serial, &l.Expected, &l.Counted, &l.Result, &l.Where)
	})
	return d, e
}

// CloseInventory проводит расхождения: недостача — экземпляры в lost и списание количества (движение adjust
// from_location), излишек — приход ненайденных в учёте серийных и количества (adjust to_location). Экземпляры,
// найденные, но числящиеся в другом месте/у держателя (elsewhere), не перемещаются автоматически — только в отчёт.
func (s Store) CloseInventory(ctx context.Context, tx pgx.Tx, tenant, actor, id string) (InventoryDetail, error) {
	if _, e := tx.Exec(ctx, "SELECT 1 FROM warehouse.inventories WHERE tenant_id=$1 AND inventory_id=$2 FOR UPDATE", tenant, id); e != nil {
		return InventoryDetail{}, e
	}
	d, e := s.InventoryDetail(ctx, tx, tenant, id)
	if e != nil {
		return d, e
	}
	if d.State != "open" {
		return d, domain.Conflict
	}
	var counted bool
	if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM warehouse.inventory_counts WHERE tenant_id=$1 AND inventory_id=$2)", tenant, id).Scan(&counted); e != nil {
		return d, e
	}
	if !counted {
		return d, domain.Invalid // закрыть без введённого факта нельзя (иначе всё — недостача)
	}
	var at time.Time
	if e = tx.QueryRow(ctx, "SELECT now()").Scan(&at); e != nil {
		return d, e
	}
	basis := "Инвентаризация " + d.ActNo + ": " + d.Basis
	if len([]rune(basis)) > 256 {
		basis = string([]rune(basis)[:256])
	}
	newMove := func(from, to *string) (string, error) {
		mid := identifier.New()
		act, e := nextAct(ctx, tx, tenant, at)
		if e != nil {
			return "", e
		}
		_, e = tx.Exec(ctx, `INSERT INTO warehouse.movements(tenant_id,movement_id,kind,act_no,occurred_at,actor_ref,basis,from_location,to_location) VALUES($1,$2,'adjust',$3,$4,$5,$6,$7,$8)`, tenant, mid, act, at, actor, basis, from, to)
		return mid, e
	}
	var shortage, surplus string
	lineNo := map[string]int{}
	addLine := func(mid, item string, unit *string, q float64) error {
		lineNo[mid]++
		_, e := tx.Exec(ctx, "INSERT INTO warehouse.movement_lines(tenant_id,movement_id,line_no,item_id,unit_id,quantity) VALUES($1,$2,$3,$4,$5,$6)", tenant, mid, lineNo[mid], item, unit, q)
		return conflict(e)
	}
	loc := d.Location
	for _, l := range d.Lines {
		switch {
		case l.Result == "shortage":
			if shortage == "" {
				if shortage, e = newMove(&loc, nil); e != nil {
					return d, e
				}
			}
			if l.UnitID != nil {
				// резерв на пропавший экземпляр снимается; экземпляр — lost
				if _, e = tx.Exec(ctx, "UPDATE warehouse.reservations SET state='cancelled' WHERE tenant_id=$1 AND unit_id=$2 AND state='active'", tenant, *l.UnitID); e != nil {
					return d, e
				}
				tag, e := tx.Exec(ctx, "UPDATE warehouse.units SET state='lost',location_id=NULL,revision=revision+1 WHERE tenant_id=$1 AND unit_id=$2 AND location_id=$3 AND state IN ('in_stock','reserved')", tenant, *l.UnitID, loc)
				if e != nil {
					return d, e
				}
				if tag.RowsAffected() == 0 {
					return d, domain.Conflict
				}
				if e = addLine(shortage, l.Item, l.UnitID, 1); e != nil {
					return d, e
				}
			} else {
				q := l.Expected - *l.Counted
				// недостача количества; если зарезервировано больше нового остатка — конфликт: сначала снять резервы
				tag, e := tx.Exec(ctx, "UPDATE warehouse.stock SET quantity=quantity-$4 WHERE tenant_id=$1 AND item_id=$2 AND location_id=$3 AND quantity-reserved>=$4", tenant, l.Item, loc, q)
				if e != nil {
					return d, conflict(e)
				}
				if tag.RowsAffected() == 0 {
					return d, domain.Conflict
				}
				if e = addLine(shortage, l.Item, nil, q); e != nil {
					return d, e
				}
			}
		case l.Result == "surplus":
			if surplus == "" {
				if surplus, e = newMove(nil, &loc); e != nil {
					return d, e
				}
			}
			if l.Serial != nil {
				unit := identifier.New()
				if _, e = tx.Exec(ctx, "INSERT INTO warehouse.units(tenant_id,unit_id,item_id,serial,state,location_id) VALUES($1,$2,$3,$4,'in_stock',$5)", tenant, unit, l.Item, *l.Serial, loc); e != nil {
					return d, conflict(e)
				}
				if e = addLine(surplus, l.Item, &unit, 1); e != nil {
					return d, e
				}
			} else {
				q := *l.Counted - l.Expected
				if _, e = tx.Exec(ctx, `INSERT INTO warehouse.stock(tenant_id,item_id,location_id,quantity) VALUES($1,$2,$3,$4)
ON CONFLICT (tenant_id,item_id,location_id) DO UPDATE SET quantity=warehouse.stock.quantity+excluded.quantity`, tenant, l.Item, loc, q); e != nil {
					return d, conflict(e)
				}
				if e = addLine(surplus, l.Item, nil, q); e != nil {
					return d, e
				}
			}
		}
	}
	if _, e = tx.Exec(ctx, "UPDATE warehouse.inventories SET state='closed',closed_at=$3,closed_by=$4,shortage_movement=$5,surplus_movement=$6 WHERE tenant_id=$1 AND inventory_id=$2",
		tenant, id, at, actor, nullable(shortage), nullable(surplus)); e != nil {
		return d, e
	}
	return s.InventoryDetail(ctx, tx, tenant, id)
}

// CancelInventory отменяет открытую инвентаризацию без корректировок (место снова доступно).
func (s Store) CancelInventory(ctx context.Context, tx pgx.Tx, tenant, actor, id string) (InventoryDetail, error) {
	tag, e := tx.Exec(ctx, "UPDATE warehouse.inventories SET state='cancelled',closed_at=now(),closed_by=$3 WHERE tenant_id=$1 AND inventory_id=$2 AND state='open'", tenant, id, actor)
	if e != nil {
		return InventoryDetail{}, e
	}
	if tag.RowsAffected() == 0 {
		if _, e = s.inventory(ctx, tx, tenant, id); e != nil {
			return InventoryDetail{}, e
		}
		return InventoryDetail{}, domain.Conflict
	}
	return s.InventoryDetail(ctx, tx, tenant, id)
}

// Inventories — последние инвентаризации организации.
func (Store) Inventories(ctx context.Context, tx pgx.Tx, tenant string, limit int) ([]Inventory, error) {
	rows, e := tx.Query(ctx, `SELECT inventory_id::text,location_id::text,act_no,basis,state,started_at,started_by,closed_at,shortage_movement::text,surplus_movement::text
FROM warehouse.inventories WHERE tenant_id=$1 ORDER BY started_at DESC LIMIT $2`, tenant, limit)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Inventory, error) {
		var v Inventory
		return v, r.Scan(&v.ID, &v.Location, &v.ActNo, &v.Basis, &v.State, &v.StartedAt, &v.StartedBy, &v.ClosedAt, &v.Shortage, &v.Surplus)
	})
}
