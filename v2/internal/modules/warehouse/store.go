package warehouse

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
)

type Store struct{}

type Location struct {
	ID     string  `json:"location_id"`
	Site   string  `json:"site_id"`
	Parent *string `json:"parent_id"`
	Kind   string  `json:"kind"`
	Name   string  `json:"name"`
	Active bool    `json:"active"`
}

type Item struct {
	ID       string  `json:"item_id"`
	Name     string  `json:"name"`
	Kind     string  `json:"kind"`
	Unit     string  `json:"unit"`
	Category *string `json:"category"`
	Active   bool    `json:"active"`
}

type Unit struct {
	ID          string  `json:"unit_id"`
	Item        string  `json:"item_id"`
	ItemName    string  `json:"item_name"`
	Serial      string  `json:"serial"`
	InventoryNo *string `json:"inventory_no"`
	Asset       *string `json:"asset_uid"`
	State       string  `json:"state"`
	Location    *string `json:"location_id"`
	Holder      *string `json:"holder_id"`
	InstalledOn *string `json:"installed_on"`
}

type StockRow struct {
	Item     string  `json:"item_id"`
	ItemName string  `json:"item_name"`
	Unit     string  `json:"unit"`
	Location string  `json:"location_id"`
	Quantity float64 `json:"quantity"`
	Reserved float64 `json:"reserved"`
}

// Line — строка операции: серийный экземпляр (UnitID) или количество позиции (ItemID+Quantity). Для прихода
// серийного экземпляра — ItemID+Serial(+InventoryNo, Asset): экземпляр создаётся этой операцией.
type Line struct {
	UnitID      string  `json:"unit_id,omitempty"`
	ItemID      string  `json:"item_id,omitempty"`
	Quantity    float64 `json:"quantity,omitempty"`
	Serial      string  `json:"serial,omitempty"`
	InventoryNo string  `json:"inventory_no,omitempty"`
	Asset       string  `json:"asset_uid,omitempty"`
}

// Operation — одна складская операция (одна запись журнала и акт).
type Operation struct {
	Kind         string `json:"kind"`
	Basis        string `json:"basis"`
	Note         string `json:"note,omitempty"`
	FromLocation string `json:"from_location,omitempty"`
	ToLocation   string `json:"to_location,omitempty"`
	FromHolder   string `json:"from_holder,omitempty"`
	ToHolder     string `json:"to_holder,omitempty"`
	Asset        string `json:"asset_uid,omitempty"` // install/remove: актив, на который ставят / с которого снимают
	Lines        []Line `json:"lines"`
}

type MovementLine struct {
	No       int     `json:"line_no"`
	Item     string  `json:"item_id"`
	ItemName string  `json:"item_name"`
	ItemUnit string  `json:"unit"`
	UnitID   *string `json:"unit_id"`
	Serial   *string `json:"serial"`
	InvNo    *string `json:"inventory_no"`
	Quantity float64 `json:"quantity"`
}

type Movement struct {
	ID           string         `json:"movement_id"`
	Kind         string         `json:"kind"`
	ActNo        string         `json:"act_no"`
	At           time.Time      `json:"occurred_at"`
	Actor        string         `json:"actor_ref"`
	Basis        string         `json:"basis"`
	Note         *string        `json:"note"`
	FromLocation *string        `json:"from_location"`
	ToLocation   *string        `json:"to_location"`
	FromHolder   *string        `json:"from_holder"`
	ToHolder     *string        `json:"to_holder"`
	Asset        *string        `json:"asset_uid"`
	Reverses     *string        `json:"reverses"`
	Lines        []MovementLine `json:"lines"`
}

// Kinds — допустимые виды операций (reverse — сторно, отдельной функцией позже).
var Kinds = []string{"receive", "issue", "return", "transfer", "repair_out", "repair_in", "install", "remove", "write_off"}

func text(v string, min, max int) bool { n := len([]rune(v)); return n >= min && n <= max }

func conflict(e error) error {
	var pg *pgconn.PgError
	if errors.As(e, &pg) && (pg.Code == "23505" || pg.Code == "23514" || pg.Code == "23503") {
		return domain.Conflict
	}
	return e
}

func (Store) CreateLocation(ctx context.Context, tx pgx.Tx, tenant string, l Location) (Location, error) {
	l.Name = strings.TrimSpace(l.Name)
	if !identifier.Valid(l.Site) || !text(l.Name, 1, 128) || (l.Kind != "warehouse" && l.Kind != "bin" && l.Kind != "repair") || (l.Kind == "bin") != (l.Parent != nil) {
		return l, domain.Invalid
	}
	if l.Parent != nil {
		var site string
		if e := tx.QueryRow(ctx, "SELECT site_id::text FROM warehouse.locations WHERE tenant_id=$1 AND location_id=$2 AND kind='warehouse'", tenant, *l.Parent).Scan(&site); e != nil || site != l.Site {
			return l, domain.Invalid // ячейка — только внутри склада той же площадки
		}
	}
	l.ID, l.Active = identifier.New(), true
	_, e := tx.Exec(ctx, "INSERT INTO warehouse.locations(tenant_id,location_id,site_id,parent_id,kind,name) VALUES($1,$2,$3,$4,$5,$6)", tenant, l.ID, l.Site, l.Parent, l.Kind, l.Name)
	return l, conflict(e)
}

func (Store) Locations(ctx context.Context, tx pgx.Tx, tenant string) ([]Location, error) {
	rows, e := tx.Query(ctx, "SELECT location_id::text,site_id::text,parent_id::text,kind,name,active FROM warehouse.locations WHERE tenant_id=$1 ORDER BY kind<>'warehouse',name LIMIT 1000", tenant)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Location, error) {
		var l Location
		return l, r.Scan(&l.ID, &l.Site, &l.Parent, &l.Kind, &l.Name, &l.Active)
	})
}

func (Store) CreateItem(ctx context.Context, tx pgx.Tx, tenant string, it Item) (Item, error) {
	it.Name = strings.TrimSpace(it.Name)
	if it.Unit == "" {
		it.Unit = "шт"
	}
	if !text(it.Name, 1, 256) || (it.Kind != "serial" && it.Kind != "quantity") || !text(it.Unit, 1, 16) || (it.Category != nil && !text(*it.Category, 0, 64)) || (it.Kind == "serial" && it.Unit != "шт") {
		return it, domain.Invalid
	}
	it.ID, it.Active = identifier.New(), true
	_, e := tx.Exec(ctx, "INSERT INTO warehouse.items(tenant_id,item_id,name,kind,unit,category) VALUES($1,$2,$3,$4,$5,$6)", tenant, it.ID, it.Name, it.Kind, it.Unit, it.Category)
	return it, conflict(e)
}

func (Store) Items(ctx context.Context, tx pgx.Tx, tenant string) ([]Item, error) {
	rows, e := tx.Query(ctx, "SELECT item_id::text,name,kind,unit,category,active FROM warehouse.items WHERE tenant_id=$1 ORDER BY lower(name) LIMIT 2000", tenant)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Item, error) {
		var it Item
		return it, r.Scan(&it.ID, &it.Name, &it.Kind, &it.Unit, &it.Category, &it.Active)
	})
}

// UnitFilter — выборка экземпляров: по состоянию, держателю, месту, активу (на который установлен или который сам).
type UnitFilter struct{ State, Holder, Location, Asset, Query string }

func (Store) Units(ctx context.Context, tx pgx.Tx, tenant string, f UnitFilter, limit int) ([]Unit, error) {
	rows, e := tx.Query(ctx, `SELECT u.unit_id::text,u.item_id::text,i.name,u.serial,u.inventory_no,u.asset_uid::text,u.state,u.location_id::text,u.holder_id::text,u.installed_on::text
FROM warehouse.units u JOIN warehouse.items i USING(tenant_id,item_id) WHERE u.tenant_id=$1
AND ($2='' OR u.state=$2) AND ($3='' OR u.holder_id::text=$3) AND ($4='' OR u.location_id::text=$4)
AND ($5='' OR u.asset_uid::text=$5 OR u.installed_on::text=$5)
AND ($6='' OR lower(u.serial) LIKE '%'||lower($6)||'%' OR lower(COALESCE(u.inventory_no,'')) LIKE '%'||lower($6)||'%' OR lower(i.name) LIKE '%'||lower($6)||'%')
ORDER BY i.name,u.serial LIMIT $7`, tenant, f.State, f.Holder, f.Location, f.Asset, f.Query, limit)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Unit, error) {
		var u Unit
		return u, r.Scan(&u.ID, &u.Item, &u.ItemName, &u.Serial, &u.InventoryNo, &u.Asset, &u.State, &u.Location, &u.Holder, &u.InstalledOn)
	})
}

func (Store) Stock(ctx context.Context, tx pgx.Tx, tenant, location string) ([]StockRow, error) {
	rows, e := tx.Query(ctx, `SELECT s.item_id::text,i.name,i.unit,s.location_id::text,s.quantity::float8,s.reserved::float8 FROM warehouse.stock s JOIN warehouse.items i USING(tenant_id,item_id)
WHERE s.tenant_id=$1 AND ($2='' OR s.location_id::text=$2) AND s.quantity>0 ORDER BY i.name LIMIT 2000`, tenant, location)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (StockRow, error) {
		var s StockRow
		return s, r.Scan(&s.Item, &s.ItemName, &s.Unit, &s.Location, &s.Quantity, &s.Reserved)
	})
}

func nullable(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// locationKind — вид места этой организации ("" — нет такого/неактивно).
func locationKind(ctx context.Context, tx pgx.Tx, tenant, id string) (string, error) {
	var kind string
	e := tx.QueryRow(ctx, "SELECT kind FROM warehouse.locations WHERE tenant_id=$1 AND location_id=$2 AND active", tenant, id).Scan(&kind)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", nil
	}
	return kind, e
}

// Move проводит операцию целиком в транзакции вызывающего: проверки вида, условные обновления экземпляров и
// остатков (0 строк — Conflict: экземпляр уже выдан/не там, остатка не хватает), запись журнала и номер акта.
// Возвращает движение; затронутые активы (списание/установка) — для действий вызывающего (вывод из учёта, аудит).
func (s Store) Move(ctx context.Context, tx pgx.Tx, tenant, actor string, op Operation) (Movement, error) {
	var m Movement
	if !text(strings.TrimSpace(op.Basis), 1, 256) || !text(op.Note, 0, 1024) || len(op.Lines) == 0 || len(op.Lines) > 500 {
		return m, domain.Invalid
	}
	for _, id := range []string{op.FromLocation, op.ToLocation, op.FromHolder, op.ToHolder, op.Asset} {
		if id != "" && !identifier.Valid(id) {
			return m, domain.Invalid
		}
	}
	need := func(from, to, fromH, toH, asset bool) bool {
		return (op.FromLocation != "") == from && (op.ToLocation != "") == to && (op.FromHolder != "") == fromH && (op.ToHolder != "") == toH && (op.Asset != "") == asset
	}
	fromKind, toKind := "", ""
	var e error
	if op.FromLocation != "" {
		if fromKind, e = locationKind(ctx, tx, tenant, op.FromLocation); e != nil || fromKind == "" {
			return m, orInvalid(e)
		}
	}
	if op.ToLocation != "" {
		if toKind, e = locationKind(ctx, tx, tenant, op.ToLocation); e != nil || toKind == "" {
			return m, orInvalid(e)
		}
	}
	stockKind := func(k string) bool { return k == "warehouse" || k == "bin" }
	switch op.Kind {
	case "receive":
		if !need(false, true, false, false, false) || !stockKind(toKind) {
			return m, domain.Invalid
		}
	case "issue":
		if !need(true, false, false, true, false) || !stockKind(fromKind) {
			return m, domain.Invalid
		}
	case "return":
		if !need(false, true, true, false, false) || !stockKind(toKind) {
			return m, domain.Invalid
		}
	case "transfer":
		if !need(true, true, false, false, false) || !stockKind(fromKind) || !stockKind(toKind) || op.FromLocation == op.ToLocation {
			return m, domain.Invalid
		}
	case "repair_out":
		// со склада или от держателя — в место ремонта
		if op.ToLocation == "" || toKind != "repair" || op.ToHolder != "" || op.Asset != "" || (op.FromLocation == "") == (op.FromHolder == "") || (op.FromLocation != "" && !stockKind(fromKind)) {
			return m, domain.Invalid
		}
	case "repair_in":
		if !need(true, true, false, false, false) || fromKind != "repair" || !stockKind(toKind) {
			return m, domain.Invalid
		}
	case "install":
		if !need(true, false, false, false, true) || !stockKind(fromKind) {
			return m, domain.Invalid
		}
	case "remove":
		if !need(false, true, false, false, true) || !stockKind(toKind) {
			return m, domain.Invalid
		}
	case "write_off":
		if op.ToLocation != "" || op.ToHolder != "" || op.Asset != "" || (op.FromLocation == "") == (op.FromHolder == "") {
			return m, domain.Invalid
		}
	default:
		return m, domain.Invalid
	}
	for _, h := range []string{op.FromHolder, op.ToHolder} {
		if h == "" {
			continue
		}
		var ok bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM responsibility.subjects WHERE tenant_id=$1 AND subject_id=$2 AND active)", tenant, h).Scan(&ok); e != nil || !ok {
			return m, orInvalid(e)
		}
	}
	if op.Asset != "" {
		var ok bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2 AND merged_into IS NULL AND retired_at IS NULL)", tenant, op.Asset).Scan(&ok); e != nil || !ok {
			return m, orInvalid(e)
		}
	}

	m = Movement{ID: identifier.New(), Kind: op.Kind, Actor: actor, Basis: strings.TrimSpace(op.Basis), Note: nullable(op.Note), FromLocation: nullable(op.FromLocation), ToLocation: nullable(op.ToLocation), FromHolder: nullable(op.FromHolder), ToHolder: nullable(op.ToHolder), Asset: nullable(op.Asset)}
	if e = tx.QueryRow(ctx, "SELECT now()").Scan(&m.At); e != nil {
		return m, e
	}
	var no int
	if e = tx.QueryRow(ctx, `INSERT INTO warehouse.act_counters(tenant_id,year,last) VALUES($1,$2,1)
ON CONFLICT (tenant_id,year) DO UPDATE SET last=warehouse.act_counters.last+1 RETURNING last`, tenant, m.At.Year()).Scan(&no); e != nil {
		return m, e
	}
	m.ActNo = fmt.Sprintf("%d-%06d", m.At.Year(), no)
	if _, e = tx.Exec(ctx, `INSERT INTO warehouse.movements(tenant_id,movement_id,kind,act_no,occurred_at,actor_ref,basis,note,from_location,to_location,from_holder,to_holder,asset_uid)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, tenant, m.ID, m.Kind, m.ActNo, m.At, actor, m.Basis, m.Note, m.FromLocation, m.ToLocation, m.FromHolder, m.ToHolder, m.Asset); e != nil {
		return m, conflict(e)
	}
	seen := map[string]bool{}
	for i, l := range op.Lines {
		unit, item, qty, e := s.applyLine(ctx, tx, tenant, op, l)
		if e != nil {
			return m, e
		}
		if unit != "" {
			if seen[unit] {
				return m, domain.Invalid // один экземпляр дважды в одной операции
			}
			seen[unit] = true
		}
		if _, e = tx.Exec(ctx, "INSERT INTO warehouse.movement_lines(tenant_id,movement_id,line_no,item_id,unit_id,quantity) VALUES($1,$2,$3,$4,$5,$6)", tenant, m.ID, i+1, item, nullable(unit), qty); e != nil {
			return m, conflict(e)
		}
	}
	return s.Movement(ctx, tx, tenant, m.ID)
}

func orInvalid(e error) error {
	if e != nil {
		return e
	}
	return domain.Invalid
}

func itemKind(ctx context.Context, tx pgx.Tx, tenant, item string) (string, error) {
	var kind string
	e := tx.QueryRow(ctx, "SELECT kind FROM warehouse.items WHERE tenant_id=$1 AND item_id=$2 AND active", tenant, item).Scan(&kind)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", domain.Invalid
	}
	return kind, e
}

// applyLine — одна строка: условное обновление экземпляра или остатка. Возвращает unit_id (для серийного), позицию и количество.
func (Store) applyLine(ctx context.Context, tx pgx.Tx, tenant string, op Operation, l Line) (string, string, float64, error) {
	if l.UnitID == "" && op.Kind == "receive" && l.Serial != "" {
		// приход серийного экземпляра: создаётся этой операцией
		if kind, e := itemKind(ctx, tx, tenant, l.ItemID); e != nil || kind != "serial" || !text(strings.TrimSpace(l.Serial), 1, 128) || !text(l.InventoryNo, 0, 64) || (l.Asset != "" && !identifier.Valid(l.Asset)) {
			return "", "", 0, orInvalid(e)
		}
		unit := identifier.New()
		_, e := tx.Exec(ctx, "INSERT INTO warehouse.units(tenant_id,unit_id,item_id,serial,inventory_no,asset_uid,state,location_id) VALUES($1,$2,$3,$4,$5,$6,'in_stock',$7)",
			tenant, unit, l.ItemID, strings.TrimSpace(l.Serial), nullable(strings.TrimSpace(l.InventoryNo)), nullable(l.Asset), op.ToLocation)
		return unit, l.ItemID, 1, conflict(e)
	}
	if l.UnitID != "" {
		if !identifier.Valid(l.UnitID) || l.ItemID != "" || l.Quantity != 0 && l.Quantity != 1 {
			return "", "", 0, domain.Invalid
		}
		// условие «откуда» и новое состояние — по одному фиксированному запросу на вид операции; 0 строк —
		// экземпляр не в ожидаемом месте/состоянии (двойная выдача, уже возвращён и т. п.)
		var row pgx.Row
		switch {
		case op.Kind == "issue":
			// свободный экземпляр или зарезервированный за этим же получателем (резерв закрывается ниже)
			row = tx.QueryRow(ctx, `UPDATE warehouse.units u SET state='issued',location_id=NULL,holder_id=$4,revision=revision+1 WHERE tenant_id=$1 AND unit_id=$2 AND location_id=$3
AND (state='in_stock' OR (state='reserved' AND EXISTS(SELECT 1 FROM warehouse.reservations r WHERE r.tenant_id=u.tenant_id AND r.unit_id=u.unit_id AND r.state='active' AND r.holder_id=$4))) RETURNING item_id::text`, tenant, l.UnitID, op.FromLocation, op.ToHolder)
		case op.Kind == "return":
			row = tx.QueryRow(ctx, `UPDATE warehouse.units SET state='in_stock',holder_id=NULL,location_id=$4,revision=revision+1 WHERE tenant_id=$1 AND unit_id=$2 AND state='issued' AND holder_id=$3 RETURNING item_id::text`, tenant, l.UnitID, op.FromHolder, op.ToLocation)
		case op.Kind == "transfer":
			row = tx.QueryRow(ctx, `UPDATE warehouse.units SET location_id=$4,revision=revision+1 WHERE tenant_id=$1 AND unit_id=$2 AND state='in_stock' AND location_id=$3 RETURNING item_id::text`, tenant, l.UnitID, op.FromLocation, op.ToLocation)
		case op.Kind == "repair_out" && op.FromLocation != "":
			row = tx.QueryRow(ctx, `UPDATE warehouse.units SET state='in_repair',location_id=$4,revision=revision+1 WHERE tenant_id=$1 AND unit_id=$2 AND state='in_stock' AND location_id=$3 RETURNING item_id::text`, tenant, l.UnitID, op.FromLocation, op.ToLocation)
		case op.Kind == "repair_out":
			row = tx.QueryRow(ctx, `UPDATE warehouse.units SET state='in_repair',holder_id=NULL,location_id=$4,revision=revision+1 WHERE tenant_id=$1 AND unit_id=$2 AND state='issued' AND holder_id=$3 RETURNING item_id::text`, tenant, l.UnitID, op.FromHolder, op.ToLocation)
		case op.Kind == "repair_in":
			row = tx.QueryRow(ctx, `UPDATE warehouse.units SET state='in_stock',location_id=$4,revision=revision+1 WHERE tenant_id=$1 AND unit_id=$2 AND state='in_repair' AND location_id=$3 RETURNING item_id::text`, tenant, l.UnitID, op.FromLocation, op.ToLocation)
		case op.Kind == "install":
			row = tx.QueryRow(ctx, `UPDATE warehouse.units SET state='installed',location_id=NULL,installed_on=$4,revision=revision+1 WHERE tenant_id=$1 AND unit_id=$2 AND state='in_stock' AND location_id=$3 AND asset_uid IS DISTINCT FROM $4::uuid RETURNING item_id::text`, tenant, l.UnitID, op.FromLocation, op.Asset)
		case op.Kind == "remove":
			row = tx.QueryRow(ctx, `UPDATE warehouse.units SET state='in_stock',installed_on=NULL,location_id=$4,revision=revision+1 WHERE tenant_id=$1 AND unit_id=$2 AND state='installed' AND installed_on=$3 RETURNING item_id::text`, tenant, l.UnitID, op.Asset, op.ToLocation)
		case op.Kind == "write_off" && op.FromLocation != "":
			row = tx.QueryRow(ctx, `UPDATE warehouse.units SET state='written_off',location_id=NULL,revision=revision+1 WHERE tenant_id=$1 AND unit_id=$2 AND state IN ('in_stock','in_repair') AND location_id=$3 RETURNING item_id::text`, tenant, l.UnitID, op.FromLocation)
		case op.Kind == "write_off":
			row = tx.QueryRow(ctx, `UPDATE warehouse.units SET state='written_off',holder_id=NULL,revision=revision+1 WHERE tenant_id=$1 AND unit_id=$2 AND state='issued' AND holder_id=$3 RETURNING item_id::text`, tenant, l.UnitID, op.FromHolder)
		default:
			return "", "", 0, domain.Invalid
		}
		var item string
		e := row.Scan(&item)
		if errors.Is(e, pgx.ErrNoRows) {
			return "", "", 0, domain.Conflict
		}
		if e != nil {
			return "", "", 0, conflict(e)
		}
		if op.Kind == "issue" {
			if _, e = tx.Exec(ctx, "UPDATE warehouse.reservations SET state='fulfilled' WHERE tenant_id=$1 AND unit_id=$2 AND state='active'", tenant, l.UnitID); e != nil {
				return "", "", 0, e
			}
		}
		return l.UnitID, item, 1, nil
	}
	// количество позиции
	if kind, e := itemKind(ctx, tx, tenant, l.ItemID); e != nil || kind != "quantity" || !(l.Quantity > 0) || l.Quantity > 1e9 {
		return "", "", 0, orInvalid(e)
	}
	q := l.Quantity
	take := func(loc string) error {
		tag, e := tx.Exec(ctx, "UPDATE warehouse.stock SET quantity=quantity-$4 WHERE tenant_id=$1 AND item_id=$2 AND location_id=$3 AND quantity-reserved>=$4", tenant, l.ItemID, loc, q)
		if e != nil {
			return conflict(e)
		}
		if tag.RowsAffected() == 0 {
			return domain.Conflict // остатка (без резерва) не хватает
		}
		return nil
	}
	put := func(loc string) error {
		_, e := tx.Exec(ctx, `INSERT INTO warehouse.stock(tenant_id,item_id,location_id,quantity) VALUES($1,$2,$3,$4)
ON CONFLICT (tenant_id,item_id,location_id) DO UPDATE SET quantity=warehouse.stock.quantity+excluded.quantity`, tenant, l.ItemID, loc, q)
		return conflict(e)
	}
	var e error
	switch op.Kind {
	case "receive", "return":
		e = put(op.ToLocation) // возврат количества — на склад от держателя (остатки у людей не ведутся)
	case "issue":
		e = take(op.FromLocation) // выдача расходников — списание со склада получателю
	case "transfer":
		if e = take(op.FromLocation); e == nil {
			e = put(op.ToLocation)
		}
	case "write_off":
		if op.FromLocation == "" {
			return "", "", 0, domain.Invalid
		}
		e = take(op.FromLocation)
	default:
		return "", "", 0, domain.Invalid // ремонт/установка — только серийные экземпляры
	}
	return "", l.ItemID, q, e
}

func (Store) Movement(ctx context.Context, tx pgx.Tx, tenant, id string) (Movement, error) {
	var m Movement
	if !identifier.Valid(id) {
		return m, domain.NotFound
	}
	e := tx.QueryRow(ctx, `SELECT movement_id::text,kind,act_no,occurred_at,actor_ref,basis,note,from_location::text,to_location::text,from_holder::text,to_holder::text,asset_uid::text,reverses::text
FROM warehouse.movements WHERE tenant_id=$1 AND movement_id=$2`, tenant, id).Scan(&m.ID, &m.Kind, &m.ActNo, &m.At, &m.Actor, &m.Basis, &m.Note, &m.FromLocation, &m.ToLocation, &m.FromHolder, &m.ToHolder, &m.Asset, &m.Reverses)
	if errors.Is(e, pgx.ErrNoRows) {
		return m, domain.NotFound
	}
	if e != nil {
		return m, e
	}
	rows, e := tx.Query(ctx, `SELECT l.line_no,l.item_id::text,i.name,i.unit,l.unit_id::text,u.serial,u.inventory_no,l.quantity::float8 FROM warehouse.movement_lines l
JOIN warehouse.items i ON i.tenant_id=l.tenant_id AND i.item_id=l.item_id LEFT JOIN warehouse.units u ON u.tenant_id=l.tenant_id AND u.unit_id=l.unit_id
WHERE l.tenant_id=$1 AND l.movement_id=$2 ORDER BY l.line_no`, tenant, id)
	if e != nil {
		return m, e
	}
	m.Lines, e = pgx.CollectRows(rows, func(r pgx.CollectableRow) (MovementLine, error) {
		var l MovementLine
		return l, r.Scan(&l.No, &l.Item, &l.ItemName, &l.ItemUnit, &l.UnitID, &l.Serial, &l.InvNo, &l.Quantity)
	})
	return m, e
}

// MovementFilter — журнал: по экземпляру, держателю, месту, активу.
type MovementFilter struct{ Unit, Holder, Location, Asset string }

func (Store) Movements(ctx context.Context, tx pgx.Tx, tenant string, f MovementFilter, limit int) ([]Movement, error) {
	rows, e := tx.Query(ctx, `SELECT m.movement_id::text,m.kind,m.act_no,m.occurred_at,m.actor_ref,m.basis,m.note,m.from_location::text,m.to_location::text,m.from_holder::text,m.to_holder::text,m.asset_uid::text,m.reverses::text
FROM warehouse.movements m WHERE m.tenant_id=$1
AND ($2='' OR EXISTS(SELECT 1 FROM warehouse.movement_lines l WHERE l.tenant_id=m.tenant_id AND l.movement_id=m.movement_id AND l.unit_id::text=$2))
AND ($3='' OR m.from_holder::text=$3 OR m.to_holder::text=$3)
AND ($4='' OR m.from_location::text=$4 OR m.to_location::text=$4)
AND ($5='' OR m.asset_uid::text=$5 OR EXISTS(SELECT 1 FROM warehouse.movement_lines l JOIN warehouse.units u ON u.tenant_id=l.tenant_id AND u.unit_id=l.unit_id WHERE l.tenant_id=m.tenant_id AND l.movement_id=m.movement_id AND u.asset_uid::text=$5))
ORDER BY m.occurred_at DESC, m.act_no DESC LIMIT $6`, tenant, f.Unit, f.Holder, f.Location, f.Asset, limit)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Movement, error) {
		var m Movement
		return m, r.Scan(&m.ID, &m.Kind, &m.ActNo, &m.At, &m.Actor, &m.Basis, &m.Note, &m.FromLocation, &m.ToLocation, &m.FromHolder, &m.ToHolder, &m.Asset, &m.Reverses)
	})
}

// WrittenOffAssets — активы реестра, чьи экземпляры списаны этой операцией (вызывающий выводит их из учёта).
func (Store) WrittenOffAssets(ctx context.Context, tx pgx.Tx, tenant, movement string) ([]string, error) {
	rows, e := tx.Query(ctx, `SELECT u.asset_uid::text FROM warehouse.movement_lines l JOIN warehouse.movements m USING(tenant_id,movement_id)
JOIN warehouse.units u ON u.tenant_id=l.tenant_id AND u.unit_id=l.unit_id WHERE l.tenant_id=$1 AND l.movement_id=$2 AND m.kind='write_off' AND u.asset_uid IS NOT NULL`, tenant, movement)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// Discrepancy — расхождение остатка с журналом (пересчёт из движений, C41.03 п. 3).
type Discrepancy struct {
	Item     string  `json:"item_id"`
	Location string  `json:"location_id"`
	Stock    float64 `json:"stock"`
	Journal  float64 `json:"journal"`
}

// VerifyStock пересчитывает остатки количественных позиций из журнала движений и сравнивает с таблицей остатков.
func (Store) VerifyStock(ctx context.Context, tx pgx.Tx, tenant string) ([]Discrepancy, error) {
	rows, e := tx.Query(ctx, `WITH j AS (
 SELECT l.item_id, m.to_location AS loc, sum(l.quantity) AS q FROM warehouse.movement_lines l JOIN warehouse.movements m USING(tenant_id,movement_id)
  WHERE l.tenant_id=$1 AND l.unit_id IS NULL AND m.to_location IS NOT NULL GROUP BY 1,2
 UNION ALL
 SELECT l.item_id, m.from_location, -sum(l.quantity) FROM warehouse.movement_lines l JOIN warehouse.movements m USING(tenant_id,movement_id)
  WHERE l.tenant_id=$1 AND l.unit_id IS NULL AND m.from_location IS NOT NULL GROUP BY 1,2),
 t AS (SELECT item_id, loc, sum(q) AS q FROM j GROUP BY 1,2)
SELECT COALESCE(s.item_id,t.item_id)::text, COALESCE(s.location_id,t.loc)::text, COALESCE(s.quantity,0)::float8, COALESCE(t.q,0)::float8
FROM (SELECT * FROM warehouse.stock WHERE tenant_id=$1) s FULL JOIN t ON t.item_id=s.item_id AND t.loc=s.location_id
WHERE COALESCE(s.quantity,0) <> COALESCE(t.q,0)`, tenant)
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Discrepancy, error) {
		var d Discrepancy
		return d, r.Scan(&d.Item, &d.Location, &d.Stock, &d.Journal)
	})
}
