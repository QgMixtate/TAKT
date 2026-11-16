package itsm

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/domain"
)

// SLA (C50.01; AC W3-07): сроки реакции и решения по виду и приоритету в рабочих минутах одного календаря организации;
// пауза «ждём заявителя» (и «на согласовании» у заявок); предупреждение (warn_percent срока) и нарушение отмечаются
// фоновым проходом (Sweep) и при остановке таймера; события ticket.sla_*.v1 — во внешние системы через webhook.

// BusinessHours — рабочие часы: дни недели ISO (1 — понедельник … 7 — воскресенье), начало и конец в минутах от полуночи.
type BusinessHours struct {
	Timezone    string `json:"timezone"`
	Days        []int  `json:"days"`
	StartMinute int    `json:"start_minute"`
	EndMinute   int    `json:"end_minute"`
	WarnPercent int    `json:"warn_percent"`
}

// Policy — сроки для вида и приоритета (рабочие минуты).
type Policy struct {
	Kind       string `json:"kind"`
	Priority   int    `json:"priority"`
	Response   int    `json:"response_minutes"`
	Resolution int    `json:"resolution_minutes"`
}

type SLASettings struct {
	Hours    BusinessHours `json:"hours"`
	Policies []Policy      `json:"policies"`
	Revision string        `json:"revision"` // "0" — значения по умолчанию, ещё не сохранялись
}

// DefaultHours — пн–пт 09:00–18:00 по Москве, предупреждение на 80 % срока.
var DefaultHours = BusinessHours{Timezone: "Europe/Moscow", Days: []int{1, 2, 3, 4, 5}, StartMinute: 540, EndMinute: 1080, WarnPercent: 80}

// DefaultPolicies — сроки по умолчанию (рабочие минуты): реакция / решение.
var DefaultPolicies = []Policy{
	{"incident", 1, 30, 240}, {"incident", 2, 60, 480}, {"incident", 3, 240, 1440}, {"incident", 4, 480, 2400},
	{"request", 1, 120, 960}, {"request", 2, 240, 1440}, {"request", 3, 480, 2400}, {"request", 4, 960, 4800},
}

type calendar struct {
	loc        *time.Location
	days       [8]bool
	start, end int
}

func (h BusinessHours) calendar() (calendar, error) {
	loc, e := time.LoadLocation(h.Timezone)
	if e != nil || h.Timezone == "" || h.Timezone == "Local" {
		return calendar{}, domain.Invalid
	}
	c := calendar{loc: loc, start: h.StartMinute, end: h.EndMinute}
	if len(h.Days) < 1 || len(h.Days) > 7 || h.StartMinute < 0 || h.EndMinute > 1440 || h.EndMinute <= h.StartMinute || h.WarnPercent < 50 || h.WarnPercent > 99 {
		return c, domain.Invalid
	}
	for _, d := range h.Days {
		if d < 1 || d > 7 || c.days[d] {
			return c, domain.Invalid
		}
		c.days[d] = true
	}
	return c, nil
}

const maxCalendarDays = 3700

func (c calendar) window(day time.Time) (time.Time, time.Time, bool) {
	wd := int(day.Weekday())
	if wd == 0 {
		wd = 7
	}
	y, m, d := day.Date()
	return time.Date(y, m, d, 0, c.start, 0, 0, c.loc), time.Date(y, m, d, 0, c.end, 0, 0, c.loc), c.days[wd]
}

// Minutes — рабочие минуты между a и b.
func (c calendar) Minutes(a, b time.Time) float64 {
	if !b.After(a) {
		return 0
	}
	total := 0.0
	y, m, d := a.In(c.loc).Date()
	day := time.Date(y, m, d, 12, 0, 0, 0, c.loc)
	for i := 0; i < maxCalendarDays && !day.Add(-12*time.Hour).After(b); i++ {
		ws, we, ok := c.window(day)
		if ok {
			s, e := ws, we
			if a.After(s) {
				s = a
			}
			if b.Before(e) {
				e = b
			}
			if e.After(s) {
				total += e.Sub(s).Minutes()
			}
		}
		day = day.AddDate(0, 0, 1)
	}
	return total
}

// Add — момент, когда от a пройдёт minutes рабочих минут.
func (c calendar) Add(a time.Time, minutes float64) time.Time {
	y, m, d := a.In(c.loc).Date()
	day := time.Date(y, m, d, 12, 0, 0, 0, c.loc)
	for i := 0; i < maxCalendarDays; i++ {
		ws, we, ok := c.window(day)
		if ok {
			s := ws
			if a.After(s) {
				s = a
			}
			if we.After(s) {
				avail := we.Sub(s).Minutes()
				if minutes <= avail {
					return s.Add(time.Duration(minutes * float64(time.Minute)))
				}
				minutes -= avail
			}
		}
		day = day.AddDate(0, 0, 1)
	}
	return a.AddDate(10, 0, 0)
}

// Timer — таймер SLA в карточке и очереди.
type Timer struct {
	Metric     string     `json:"metric"`
	Target     int        `json:"target_minutes"`
	Elapsed    int        `json:"elapsed_minutes"`
	Status     string     `json:"status"` // running | paused | warning | breached | met | missed
	DueAt      *time.Time `json:"due_at"`
	WarnedAt   *time.Time `json:"warned_at"`
	BreachedAt *time.Time `json:"breached_at"`
}

type timerRow struct {
	ticket, metric       string
	target               int
	started              time.Time
	stopped, pausedSince *time.Time
	paused               float64
	warned, breached     *time.Time
}

func (c calendar) elapsed(t timerRow, now time.Time) float64 {
	end := now
	if t.stopped != nil {
		end = *t.stopped
	}
	v := c.Minutes(t.started, end) - t.paused
	if t.pausedSince != nil {
		v -= c.Minutes(*t.pausedSince, end)
	}
	return math.Max(v, 0)
}

func (c calendar) view(t timerRow, warn int, now time.Time) Timer {
	el := c.elapsed(t, now)
	out := Timer{Metric: t.metric, Target: t.target, Elapsed: int(math.Floor(el)), WarnedAt: t.warned, BreachedAt: t.breached}
	over := el > float64(t.target)
	switch {
	case t.stopped != nil && over:
		out.Status = "missed"
	case t.stopped != nil:
		out.Status = "met"
	case over:
		out.Status = "breached"
	case t.pausedSince != nil:
		out.Status = "paused"
	case el >= float64(t.target*warn)/100:
		out.Status = "warning"
	default:
		out.Status = "running"
	}
	if t.stopped == nil && t.pausedSince == nil && !over {
		due := c.Add(now, float64(t.target)-el)
		out.DueAt = &due
	}
	return out
}

// SLA — настройки организации (или значения по умолчанию).
func (Store) SLA(ctx context.Context, tx pgx.Tx, tenant string) (SLASettings, error) {
	s := SLASettings{Hours: DefaultHours, Revision: "0"}
	var days []int16
	e := tx.QueryRow(ctx, "SELECT timezone,days,start_minute,end_minute,warn_percent,revision::text FROM itsm.business_hours WHERE tenant_id=$1", tenant).
		Scan(&s.Hours.Timezone, &days, &s.Hours.StartMinute, &s.Hours.EndMinute, &s.Hours.WarnPercent, &s.Revision)
	switch {
	case errors.Is(e, pgx.ErrNoRows):
		s.Hours.Days = append([]int{}, DefaultHours.Days...)
	case e != nil:
		return s, e
	default:
		s.Hours.Days = make([]int, len(days))
		for i, d := range days {
			s.Hours.Days[i] = int(d)
		}
	}
	rows, e := tx.Query(ctx, "SELECT kind,priority,response_minutes,resolution_minutes FROM itsm.sla_policies WHERE tenant_id=$1", tenant)
	if e != nil {
		return s, e
	}
	stored, e := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Policy, error) {
		var p Policy
		return p, r.Scan(&p.Kind, &p.Priority, &p.Response, &p.Resolution)
	})
	if e != nil {
		return s, e
	}
	for _, d := range DefaultPolicies {
		for _, p := range stored {
			if p.Kind == d.Kind && p.Priority == d.Priority {
				d = p
			}
		}
		s.Policies = append(s.Policies, d)
	}
	return s, nil
}

// SetSLA сохраняет рабочие часы и сроки (все 8 строк); ревизия "0" — первое сохранение. Новые сроки действуют для
// обращений, созданных после сохранения; рабочие часы — для расчёта всех таймеров.
func (s Store) SetSLA(ctx context.Context, tx pgx.Tx, tenant string, in SLASettings) (SLASettings, error) {
	if _, e := in.Hours.calendar(); e != nil {
		return in, e
	}
	if len(in.Policies) != len(DefaultPolicies) {
		return in, domain.Invalid
	}
	seen := map[[2]any]bool{}
	for _, p := range in.Policies {
		key := [2]any{p.Kind, p.Priority}
		if (p.Kind != "incident" && p.Kind != "request") || p.Priority < 1 || p.Priority > 4 || seen[key] || p.Response < 1 || p.Response > 100000 || p.Resolution < p.Response || p.Resolution > 1000000 {
			return in, domain.Invalid
		}
		seen[key] = true
	}
	var tag interface{ RowsAffected() int64 }
	var e error
	if in.Revision == "0" {
		tag, e = tx.Exec(ctx, `INSERT INTO itsm.business_hours(tenant_id,timezone,days,start_minute,end_minute,warn_percent) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id) DO NOTHING`,
			tenant, in.Hours.Timezone, in.Hours.Days, in.Hours.StartMinute, in.Hours.EndMinute, in.Hours.WarnPercent)
	} else {
		tag, e = tx.Exec(ctx, `UPDATE itsm.business_hours SET timezone=$3,days=$4,start_minute=$5,end_minute=$6,warn_percent=$7,revision=revision+1 WHERE tenant_id=$1 AND revision::text=$2`,
			tenant, in.Revision, in.Hours.Timezone, in.Hours.Days, in.Hours.StartMinute, in.Hours.EndMinute, in.Hours.WarnPercent)
	}
	if e != nil {
		return in, pgConflict(e)
	}
	if tag.RowsAffected() == 0 {
		return in, domain.Revision
	}
	for _, p := range in.Policies {
		if _, e = tx.Exec(ctx, `INSERT INTO itsm.sla_policies(tenant_id,kind,priority,response_minutes,resolution_minutes) VALUES($1,$2,$3,$4,$5)
ON CONFLICT (tenant_id,kind,priority) DO UPDATE SET response_minutes=EXCLUDED.response_minutes,resolution_minutes=EXCLUDED.resolution_minutes`, tenant, p.Kind, p.Priority, p.Response, p.Resolution); e != nil {
			return in, pgConflict(e)
		}
	}
	return s.SLA(ctx, tx, tenant)
}

func (s Store) slaCalendar(ctx context.Context, tx pgx.Tx, tenant string) (calendar, SLASettings, error) {
	set, e := s.SLA(ctx, tx, tenant)
	if e != nil {
		return calendar{}, set, e
	}
	c, e := set.Hours.calendar()
	if e != nil {
		c, e = DefaultHours.calendar() // часовой пояс исчез из базы ОС — считаем по умолчанию, а не ломаем очередь
	}
	return c, set, e
}

// startSLA заводит таймеры реакции и решения у инцидента и заявки; заявка на согласовании — сразу на паузе.
func (s Store) startSLA(ctx context.Context, tx pgx.Tx, tenant, id, kind, state string, priority int, at time.Time) error {
	if kind != "incident" && kind != "request" {
		return nil
	}
	_, set, e := s.slaCalendar(ctx, tx, tenant)
	if e != nil {
		return e
	}
	for _, p := range set.Policies {
		if p.Kind != kind || p.Priority != priority {
			continue
		}
		var paused *time.Time
		if state == "pending_approval" {
			paused = &at
		}
		for metric, target := range map[string]int{"response": p.Response, "resolution": p.Resolution} {
			if _, e = tx.Exec(ctx, "INSERT INTO itsm.sla_timers(tenant_id,ticket_id,metric,target_minutes,started_at,paused_since) VALUES($1,$2,$3,$4,$5,$6)", tenant, id, metric, target, at, paused); e != nil {
				return e
			}
		}
	}
	return nil
}

func timers(ctx context.Context, tx pgx.Tx, tenant string, ids []string, lock bool) ([]timerRow, error) {
	var rows pgx.Rows
	var e error
	if lock {
		rows, e = tx.Query(ctx, `SELECT ticket_id::text,metric,target_minutes,started_at,stopped_at,paused_since,paused_minutes,warned_at,breached_at FROM itsm.sla_timers
WHERE tenant_id=$1 AND ticket_id::text=ANY($2) ORDER BY ticket_id,metric DESC FOR UPDATE`, tenant, ids)
	} else {
		rows, e = tx.Query(ctx, `SELECT ticket_id::text,metric,target_minutes,started_at,stopped_at,paused_since,paused_minutes,warned_at,breached_at FROM itsm.sla_timers
WHERE tenant_id=$1 AND ticket_id::text=ANY($2) ORDER BY ticket_id,metric DESC`, tenant, ids)
	}
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (timerRow, error) {
		var t timerRow
		return t, r.Scan(&t.ticket, &t.metric, &t.target, &t.started, &t.stopped, &t.pausedSince, &t.paused, &t.warned, &t.breached)
	})
}

// slaViews — таймеры обращений для карточки и очереди (response, затем resolution).
func (s Store) slaViews(ctx context.Context, tx pgx.Tx, tenant string, ids []string) (map[string][]Timer, error) {
	out := map[string][]Timer{}
	if len(ids) == 0 {
		return out, nil
	}
	c, set, e := s.slaCalendar(ctx, tx, tenant)
	if e != nil {
		return out, e
	}
	rows, e := timers(ctx, tx, tenant, ids, false)
	if e != nil {
		return out, e
	}
	var now time.Time
	if e = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
		return out, e
	}
	for _, t := range rows {
		out[t.ticket] = append(out[t.ticket], c.view(t, set.Hours.WarnPercent, now))
	}
	return out, nil
}

// slaChange — реакция таймеров на действие с обращением: respond (оператор отреагировал), pause/resume, stop (решено,
// закрыто, отменено), restart (повторное открытие: время «решено → открыто» не считается). Остановка после срока
// отмечает нарушение (событие ticket.sla_breached.v1).
func (s Store) slaChange(ctx context.Context, tx pgx.Tx, tenant, id, actor string, actions ...string) error {
	rows, e := timers(ctx, tx, tenant, []string{id}, true)
	if e != nil || len(rows) == 0 {
		return e
	}
	c, _, e := s.slaCalendar(ctx, tx, tenant)
	if e != nil {
		return e
	}
	var now time.Time
	if e = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
		return e
	}
	for _, t := range rows {
		for _, a := range actions {
			switch {
			case a == "pause" && t.stopped == nil && t.pausedSince == nil:
				t.pausedSince = &now
			case a == "resume" && t.pausedSince != nil:
				end := now
				if t.stopped != nil {
					end = *t.stopped
				}
				t.paused += c.Minutes(*t.pausedSince, end)
				t.pausedSince = nil
			case (a == "stop" || a == "respond" && t.metric == "response") && t.stopped == nil:
				if t.pausedSince != nil {
					t.paused += c.Minutes(*t.pausedSince, now)
					t.pausedSince = nil
				}
				t.stopped = &now
			case a == "restart" && t.metric == "resolution" && t.stopped != nil:
				t.paused += c.Minutes(*t.stopped, now)
				t.stopped = nil
			}
		}
		breach := t.breached == nil && c.elapsed(t, now) > float64(t.target)
		if breach {
			t.breached = &now
		}
		if _, e = tx.Exec(ctx, `UPDATE itsm.sla_timers SET stopped_at=$4,paused_since=$5,paused_minutes=$6,breached_at=$7 WHERE tenant_id=$1 AND ticket_id=$2 AND metric=$3`,
			tenant, id, t.metric, t.stopped, t.pausedSince, t.paused, t.breached); e != nil {
			return e
		}
		if breach {
			if e = s.slaMark(ctx, tx, tenant, id, actor, t.metric, "breached"); e != nil {
				return e
			}
		}
	}
	return nil
}

// slaMark — запись журнала обращения и событие во внешние системы о предупреждении/нарушении срока.
func (s Store) slaMark(ctx context.Context, tx pgx.Tx, tenant, id, actor, metric, mark string) error {
	if e := event(ctx, tx, tenant, id, actor, "sla", false, map[string]any{"metric": metric, "mark": mark}, nil); e != nil {
		return e
	}
	typ := "ticket.sla_warning.v1"
	if mark == "breached" {
		typ = "ticket.sla_breached.v1"
	}
	return s.publish(ctx, tx, tenant, id, typ, map[string]string{"metric": metric})
}

// Sweep — фоновый проход: отмечает предупреждения и нарушения у идущих таймеров организации. Возвращает число отметок.
func (s Store) Sweep(ctx context.Context, tx pgx.Tx, tenant string) (int, error) {
	c, set, e := s.slaCalendar(ctx, tx, tenant)
	if e != nil {
		return 0, e
	}
	var ids []string
	rows, e := tx.Query(ctx, `SELECT DISTINCT t.ticket_id::text FROM itsm.sla_timers t WHERE t.tenant_id=$1 AND t.stopped_at IS NULL AND t.breached_at IS NULL AND t.paused_since IS NULL LIMIT 500`, tenant)
	if e != nil {
		return 0, e
	}
	if ids, e = pgx.CollectRows(rows, pgx.RowTo[string]); e != nil || len(ids) == 0 {
		return 0, e
	}
	// блокировка обращений: переходы и проход не выдают события одного обращения одновременно
	if _, e = tx.Exec(ctx, "SELECT 1 FROM itsm.tickets WHERE tenant_id=$1 AND ticket_id::text=ANY($2) ORDER BY ticket_id FOR UPDATE", tenant, ids); e != nil {
		return 0, e
	}
	list, e := timers(ctx, tx, tenant, ids, true)
	if e != nil {
		return 0, e
	}
	var now time.Time
	if e = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
		return 0, e
	}
	n := 0
	for _, t := range list {
		if t.stopped != nil || t.pausedSince != nil || t.breached != nil {
			continue
		}
		el := c.elapsed(t, now)
		mark := ""
		switch {
		case el > float64(t.target):
			mark = "breached"
			if _, e = tx.Exec(ctx, "UPDATE itsm.sla_timers SET breached_at=$4,warned_at=COALESCE(warned_at,$4) WHERE tenant_id=$1 AND ticket_id=$2 AND metric=$3", tenant, t.ticket, t.metric, now); e != nil {
				return n, e
			}
		case t.warned == nil && el >= float64(t.target*set.Hours.WarnPercent)/100:
			mark = "warning"
			if _, e = tx.Exec(ctx, "UPDATE itsm.sla_timers SET warned_at=$4 WHERE tenant_id=$1 AND ticket_id=$2 AND metric=$3", tenant, t.ticket, t.metric, now); e != nil {
				return n, e
			}
		default:
			continue
		}
		if e = s.slaMark(ctx, tx, tenant, t.ticket, "system:sla", t.metric, mark); e != nil {
			return n, e
		}
		n++
	}
	return n, nil
}

// SLATenants — организации с идущими таймерами (для фонового прохода).
func (Store) SLATenants(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, e := tx.Query(ctx, "SELECT DISTINCT tenant_id::text FROM itsm.sla_timers WHERE stopped_at IS NULL AND breached_at IS NULL AND paused_since IS NULL LIMIT 1000")
	if e != nil {
		return nil, e
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
