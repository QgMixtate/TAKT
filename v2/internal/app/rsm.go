package app

// C54.02 — наполнение РСМ: правила автопривязки (признаки хоста → предложение/привязка), массовая привязка, импорт
// CSV «система;среда;компонент;хост». Правила и привязки хранит модуль cmdb; признаки хоста читаются здесь (имена,
// адреса, класс, ПО — из assets/inventory).

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"net/netip"
	"os"
	"path"
	"strings"
	"unicode/utf8"

	accessport "github.com/QgMixtate/surveyscan/v2/internal/modules/access/port"
	"github.com/QgMixtate/surveyscan/v2/internal/modules/cmdb"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/identifier"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/telemetry"
	"github.com/jackc/pgx/v5"
)

// rsmFeatures — признаки хоста для правил.
type rsmFeatures struct {
	Hostnames []string
	Addresses []netip.Addr
	Class     string
	Software  []string
}

func (r *Registry) rsmFeatures(ctx context.Context, tx pgx.Tx, tenant, uid string) (rsmFeatures, error) {
	var f rsmFeatures
	rows, e := tx.Query(ctx, `SELECT DISTINCT lower(normalized_value) FROM assets.asset_identifiers WHERE tenant_id=$1 AND asset_uid=$2 AND kind='hostname' AND valid_to IS NULL
UNION SELECT DISTINCT lower(value #>> '{}') FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='identity' AND field_name='hostname' AND jsonb_typeof(value)='string'`, tenant, uid)
	if e != nil {
		return f, e
	}
	for rows.Next() {
		var h string
		if e = rows.Scan(&h); e != nil {
			rows.Close()
			return f, e
		}
		f.Hostnames = append(f.Hostnames, h)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return f, e
	}
	rows, e = tx.Query(ctx, `SELECT DISTINCT ip FROM (
SELECT jsonb_array_elements(value::jsonb)->>'ip' AS ip FROM inventory.current_facts WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='network' AND fact_key LIKE '%.addresses'
UNION ALL SELECT jsonb_array_elements(value)->>'ip' FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='network' AND field_name='addresses' AND jsonb_typeof(value)='array') x WHERE ip IS NOT NULL`, tenant, uid)
	if e != nil {
		return f, e
	}
	for rows.Next() {
		var s string
		if e = rows.Scan(&s); e != nil {
			rows.Close()
			return f, e
		}
		if a, err := netip.ParseAddr(s); err == nil {
			f.Addresses = append(f.Addresses, a.Unmap())
		}
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return f, e
	}
	if e = tx.QueryRow(ctx, "SELECT COALESCE(asset_class,'unknown') FROM assets.asset_business_fields WHERE tenant_id=$1 AND asset_uid=$2", tenant, uid).Scan(&f.Class); e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return f, e
	}
	rows, e = tx.Query(ctx, `SELECT DISTINCT value #>> '{}' FROM inventory.record_facts12 WHERE tenant_id=$1 AND asset_uid=$2 AND section_name='software' AND field_name='name' AND jsonb_typeof(value)='string' LIMIT 5000`, tenant, uid)
	if e != nil {
		return f, e
	}
	for rows.Next() {
		var s string
		if e = rows.Scan(&s); e != nil {
			rows.Close()
			return f, e
		}
		f.Software = append(f.Software, strings.ToLower(s))
	}
	rows.Close()
	return f, rows.Err()
}

// ruleMatches — совпадение признаков хоста с правилом. Маска имени сравнивается с коротким и полным именем.
func ruleMatches(rule cmdb.Rule, f rsmFeatures) bool {
	switch rule.Kind {
	case "subnet":
		p, e := netip.ParsePrefix(rule.Pattern)
		if e != nil {
			return false
		}
		for _, a := range f.Addresses {
			if p.Contains(a) {
				return true
			}
		}
	case "hostname_glob":
		for _, h := range f.Hostnames {
			short, _, _ := strings.Cut(h, ".")
			if ok, _ := path.Match(rule.Pattern, h); ok {
				return true
			}
			if ok, _ := path.Match(rule.Pattern, short); ok {
				return true
			}
		}
	case "software":
		needle := strings.ToLower(rule.Pattern)
		for _, s := range f.Software {
			if strings.Contains(s, needle) {
				return true
			}
		}
	case "asset_class":
		return f.Class == rule.Pattern
	}
	return false
}

// RuleRunResult — итог прохода правил.
type RuleRunResult struct {
	Assets    int `json:"assets"`
	Bound     int `json:"bound"`
	Proposed  int `json:"proposed"`
	Conflicts int `json:"conflicts"`
}

// applyRulesTx — правила к одному хосту в транзакции. Хост под auto-правилами двух и более компонентов — конфликт:
// все совпадения идут предложениями в разбор, ничего не привязывается молча.
func (r *Registry) applyRulesTx(ctx context.Context, tx pgx.Tx, tenant, actor string, rules []cmdb.Rule, uid string, out *RuleRunResult) error {
	f, e := r.rsmFeatures(ctx, tx, tenant, uid)
	if e != nil {
		return e
	}
	var matched []cmdb.Rule
	autoComponents := map[string]bool{}
	for _, rule := range rules {
		if ruleMatches(rule, f) {
			matched = append(matched, rule)
			if rule.Mode == "auto" {
				autoComponents[rule.ComponentID] = true
			}
		}
	}
	conflict := len(autoComponents) > 1
	if conflict {
		out.Conflicts++
	}
	done := map[string]bool{} // несколько правил одного компонента — одна привязка
	for _, rule := range matched {
		if done[rule.ComponentID] {
			continue
		}
		done[rule.ComponentID] = true
		res, e := r.CMDB.ApplyRuleMatch(ctx, tx, tenant, actor, rule, uid, conflict)
		if e != nil {
			return e
		}
		switch res {
		case "bound":
			out.Bound++
		case "proposed":
			out.Proposed++
		}
	}
	out.Assets++
	return nil
}

// ApplyRSMRules прогоняет правила по хостам: assets=nil — все действующие активы тенанта (пачками, каждая —
// своя транзакция), иначе — перечисленные. Вызывается оператором (после создания правила) и после приёма наблюдения.
func (r *Registry) ApplyRSMRules(ctx context.Context, id accessport.Identity, assets []string) (RuleRunResult, error) {
	return r.applyRSMRules(ctx, id.TenantID, id.UserID, assets, func(ctx context.Context) (pgx.Tx, error) { return r.assetOperationTx(ctx, id) })
}

func (r *Registry) applyRSMRules(ctx context.Context, tenant, actor string, assets []string, begin func(context.Context) (pgx.Tx, error)) (RuleRunResult, error) {
	var out RuleRunResult
	after := ""
	for {
		tx, e := begin(ctx)
		if e != nil {
			return out, e
		}
		rules, e := r.CMDB.ActiveRules(ctx, tx, tenant)
		if e != nil || len(rules) == 0 {
			tx.Rollback(ctx)
			return out, e
		}
		batch := assets
		if assets == nil {
			batch = nil
			rows, e := tx.Query(ctx, "SELECT asset_uid::text FROM assets.assets WHERE tenant_id=$1 AND merged_into IS NULL AND asset_uid::text>$2 ORDER BY asset_uid LIMIT 500", tenant, after)
			if e != nil {
				tx.Rollback(ctx)
				return out, e
			}
			for rows.Next() {
				var uid string
				if e = rows.Scan(&uid); e != nil {
					break
				}
				batch = append(batch, uid)
			}
			rows.Close()
			if e == nil {
				e = rows.Err()
			}
			if e != nil {
				tx.Rollback(ctx)
				return out, e
			}
		}
		for _, uid := range batch {
			if !identifier.Valid(uid) {
				tx.Rollback(ctx)
				return out, domain.Invalid
			}
			if e = r.applyRulesTx(ctx, tx, tenant, actor, rules, uid, &out); e != nil {
				tx.Rollback(ctx)
				return out, e
			}
		}
		if e = tx.Commit(ctx); e != nil {
			return out, e
		}
		if assets != nil || len(batch) < 500 {
			return out, nil
		}
		after = batch[len(batch)-1]
	}
}

// applyRSMRulesAfterIngest — правила к хосту после приёма наблюдения (отдельная транзакция после фиксации приёма:
// сбой правил не отменяет приём, а виден в журнале; оператор может перезапустить проход вручную).
func (r *Registry) applyRSMRulesAfterIngest(ctx context.Context, tenant, uid string) {
	var any bool // без правил — ни транзакции с блокировкой реестра, ни чтения признаков (обычный случай)
	if e := r.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM cmdb.binding_rules WHERE tenant_id=$1 AND retired_at IS NULL AND enabled)", tenant).Scan(&any); e != nil || !any {
		return
	}
	_, e := r.applyRSMRules(ctx, tenant, "rsm:rules", []string{uid}, func(ctx context.Context) (pgx.Tx, error) {
		tx, e := r.Pool.Begin(ctx)
		if e == nil {
			if e = lockRegistry(ctx, tx, tenant); e != nil {
				tx.Rollback(ctx)
			}
		}
		return tx, e
	})
	if e != nil {
		telemetry.Log(os.Stderr, "center", "rsm_rules_after_ingest_failed")
	}
}

// BindResult — итог массовой привязки.
type BindResult struct {
	Bound    int `json:"bound"`
	Existing int `json:"existing"`
	Missing  int `json:"missing"`
}

const rsmBulkMax = 10000

// BulkBind привязывает к компоненту список хостов (Web: «все по фильтру» — список собирает клиент из выборки).
// Уже привязанные к этому компоненту пропускаются; несуществующие/поглощённые — считаются отдельно.
func (r *Registry) BulkBind(ctx context.Context, id accessport.Identity, component string, assets []string) (BindResult, error) {
	var out BindResult
	if !identifier.Valid(component) || len(assets) == 0 || len(assets) > rsmBulkMax {
		return out, domain.Invalid
	}
	tx, e := r.assetOperationTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	seen := map[string]bool{}
	for _, uid := range assets {
		uid = strings.ToLower(strings.TrimSpace(uid))
		if !identifier.Valid(uid) {
			return out, domain.Invalid
		}
		if seen[uid] {
			continue
		}
		seen[uid] = true
		var alive bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2 AND merged_into IS NULL)", id.TenantID, uid).Scan(&alive); e != nil {
			return out, e
		}
		if !alive {
			out.Missing++
			continue
		}
		var exists bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM cmdb.bindings WHERE tenant_id=$1 AND component_id=$2 AND asset_uid=$3 AND valid_to IS NULL AND status<>'rejected')", id.TenantID, component, uid).Scan(&exists); e != nil {
			return out, e
		}
		if exists {
			out.Existing++
			continue
		}
		if _, e = r.CMDB.Bind(ctx, tx, id.TenantID, id.UserID, component, uid, "manual", false); e != nil {
			return out, e
		}
		out.Bound++
	}
	return out, tx.Commit(ctx)
}

// RSMCSVFormat — первая строка файла импорта РСМ (версия формата).
const RSMCSVFormat = "surveyscan-rsm-bindings;1"

type RSMImportRow struct {
	Line    int      `json:"line"`
	System  string   `json:"system"`
	Env     string   `json:"environment"`
	Comp    string   `json:"component"`
	Host    string   `json:"host"`
	Status  string   `json:"status"` // bound | existing | will_bind | system_not_found | host_not_found | host_ambiguous | invalid
	Assets  []string `json:"asset_uids"`
	Creates []string `json:"creates"`
	Detail  string   `json:"detail,omitempty"`
}

type RSMImportResult struct {
	DryRun bool           `json:"dry_run"`
	Format string         `json:"format"`
	Counts map[string]int `json:"counts"`
	Rows   []RSMImportRow `json:"rows"`
}

var errRSMCSV = errors.New("rsm csv format")

// parseRSMCSV: строка формата, затем заголовок system;environment;component;host (порядок любой), до 10 000 строк.
func parseRSMCSV(raw []byte) ([]RSMImportRow, error) {
	raw = bytes.TrimPrefix(raw, []byte("\uFEFF"))
	if !utf8.Valid(raw) {
		return nil, errRSMCSV
	}
	head, rest, ok := bytes.Cut(raw, []byte("\n"))
	if !ok || strings.TrimRight(string(head), "\r;") != RSMCSVFormat {
		return nil, errRSMCSV
	}
	c := csv.NewReader(bytes.NewReader(rest))
	c.Comma, c.FieldsPerRecord = ';', -1
	header, e := c.Read()
	if e != nil {
		return nil, errRSMCSV
	}
	at := map[string]int{}
	for i, h := range header {
		at[strings.ToLower(strings.TrimSpace(h))] = i
	}
	for _, col := range []string{"system", "environment", "component", "host"} {
		if _, ok := at[col]; !ok {
			return nil, errRSMCSV
		}
	}
	get := func(rec []string, col string) string {
		if i := at[col]; i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}
	out := []RSMImportRow{}
	for {
		rec, e := c.Read()
		if errors.Is(e, io.EOF) {
			return out, nil
		}
		if e != nil || len(out) == rsmBulkMax {
			return nil, errRSMCSV
		}
		line, _ := c.FieldPos(0)
		out = append(out, RSMImportRow{Line: line + 1, System: get(rec, "system"), Env: get(rec, "environment"), Comp: get(rec, "component"), Host: get(rec, "host"), Assets: []string{}, Creates: []string{}})
	}
}

// resolveHosts: UID актива, IP-адрес, маска имени (* ?) или имя хоста (короткое или полное). Имя, совпавшее с
// несколькими активами, — неоднозначно; маска может дать много активов (до 10 000).
func (r *Registry) resolveHosts(ctx context.Context, tx pgx.Tx, tenant, host string) ([]string, bool, error) {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || len(h) > 256 {
		return nil, false, nil
	}
	query, arg, glob := "", any(h), false
	switch {
	case identifier.Valid(h):
		query = "SELECT asset_uid::text FROM assets.assets WHERE tenant_id=$1 AND asset_uid=$2::uuid AND merged_into IS NULL"
	case func() bool { _, e := netip.ParseAddr(h); return e == nil }():
		query = `SELECT DISTINCT a.asset_uid::text FROM assets.assets a WHERE a.tenant_id=$1 AND a.merged_into IS NULL AND (
EXISTS(SELECT 1 FROM inventory.record_facts12 f WHERE f.tenant_id=a.tenant_id AND f.asset_uid=a.asset_uid AND f.section_name='network' AND f.field_name='addresses' AND jsonb_typeof(f.value)='array' AND f.value @> jsonb_build_array(jsonb_build_object('ip',$2::text)))
OR EXISTS(SELECT 1 FROM inventory.current_facts f WHERE f.tenant_id=a.tenant_id AND f.asset_uid=a.asset_uid AND f.section_name='network' AND f.fact_key LIKE '%.addresses' AND f.value::jsonb @> jsonb_build_array(jsonb_build_object('ip',$2::text)))) LIMIT 10001`
	default:
		if strings.ContainsAny(h, "*?") {
			glob = true
			arg = strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_", "*", "%", "?", "_").Replace(h)
		}
		query = `SELECT DISTINCT a.asset_uid::text FROM assets.assets a JOIN assets.asset_identifiers i ON i.tenant_id=a.tenant_id AND i.asset_uid=a.asset_uid
WHERE a.tenant_id=$1 AND a.merged_into IS NULL AND i.kind='hostname' AND i.valid_to IS NULL AND (lower(i.normalized_value) LIKE $2 OR split_part(lower(i.normalized_value),'.',1) LIKE $2) LIMIT 10001`
	}
	rows, e := tx.Query(ctx, query, tenant, arg)
	if e != nil {
		return nil, glob, e
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var uid string
		if e = rows.Scan(&uid); e != nil {
			return nil, glob, e
		}
		out = append(out, uid)
	}
	return out, glob, rows.Err()
}

// ImportRSMCSV — импорт привязок с предпросмотром (dryRun: ничего не меняется, показывается, что будет создано и
// привязано) и отчётом расхождений по строкам. Система должна существовать; среда и компонент создаются.
func (r *Registry) ImportRSMCSV(ctx context.Context, id accessport.Identity, raw []byte, dryRun bool) (RSMImportResult, error) {
	out := RSMImportResult{DryRun: dryRun, Format: RSMCSVFormat, Counts: map[string]int{}, Rows: []RSMImportRow{}}
	rows, e := parseRSMCSV(raw)
	if e != nil {
		return out, domain.Invalid
	}
	tx, e := r.assetOperationTx(ctx, id)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	actor := "user:" + id.UserID
	for _, row := range rows {
		row.Status = "invalid"
		uids, glob, e := r.resolveHosts(ctx, tx, id.TenantID, row.Host)
		if e != nil {
			return out, e
		}
		component, creates, e := r.CMDB.ComponentPath(ctx, tx, id.TenantID, actor, row.System, row.Env, row.Comp, !dryRun)
		switch {
		case errors.Is(e, domain.Invalid):
			row.Detail = "пустые или слишком длинные имена"
		case errors.Is(e, domain.NotFound):
			row.Status = "system_not_found"
		case e != nil:
			return out, e
		case len(uids) == 0:
			row.Status = "host_not_found"
		case len(uids) > 1 && !glob:
			row.Status, row.Assets = "host_ambiguous", uids
		case len(uids) > rsmBulkMax:
			row.Detail = "маска даёт больше 10 000 хостов"
		default:
			row.Assets, row.Creates = uids, creates
			if row.Creates == nil {
				row.Creates = []string{}
			}
			row.Status = "existing"
			for _, uid := range uids {
				exists := false
				if component != "" {
					if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM cmdb.bindings WHERE tenant_id=$1 AND component_id=$2 AND asset_uid=$3 AND valid_to IS NULL AND status<>'rejected')", id.TenantID, component, uid).Scan(&exists); e != nil {
						return out, e
					}
				}
				if exists {
					continue
				}
				if dryRun {
					row.Status = "will_bind"
					continue
				}
				if _, e = r.CMDB.Bind(ctx, tx, id.TenantID, actor, component, uid, "import", false); e != nil {
					return out, e
				}
				row.Status = "bound"
			}
		}
		out.Counts[row.Status]++
		out.Rows = append(out.Rows, row)
	}
	if dryRun {
		return out, nil
	}
	if e = r.Audit.Record(ctx, tx, id.TenantID, id.UserID, "cmdb.rsm_imported", "rsm_import", identifier.New()); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
