package itsm

import (
	"context"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/messaging"
)

// События обращений для внешних систем (C50.02; AC W3-08): ticket.*.v1 в outbox платформы — доставка существующим
// webhook (C31.03) «как минимум один раз»; получатель отбрасывает повторы по event_id. Тексты (описание, комментарии)
// в событие не попадают: номер, вид, состояние, приоритет. Версия агрегата — порядковый номер события обращения.
func (Store) publish(ctx context.Context, tx pgx.Tx, tenant, id, typ string, extra map[string]string) error {
	var kind, number, state string
	var priority, version int
	if e := tx.QueryRow(ctx, `SELECT t.kind,t.number,t.state,t.priority,(SELECT COALESCE(max(o.aggregate_version::numeric),0)::int+1 FROM messaging.outbox_events o
WHERE o.tenant_id=t.tenant_id AND o.aggregate_type='ticket' AND o.aggregate_id=t.ticket_id) FROM itsm.tickets t WHERE t.tenant_id=$1 AND t.ticket_id=$2`, tenant, id).
		Scan(&kind, &number, &state, &priority, &version); e != nil {
		return e
	}
	data := map[string]string{"ticket_id": id, "number": number, "kind": kind, "state": state, "priority": strconv.Itoa(priority)}
	for k, v := range extra {
		data[k] = v
	}
	return messaging.Writer{}.Emit(ctx, tx, messaging.Event{Tenant: tenant, Producer: "ITSM", Aggregate: "ticket", AssetID: id, Version: strconv.Itoa(version), Type: typ, Data: data})
}
