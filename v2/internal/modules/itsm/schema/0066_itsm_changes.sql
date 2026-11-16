-- Owner: itsm; C49 (AC W3-06): изменения — окно (начало/конец), риск, план работ и план отката; затронутые активы и
-- сервисы — связи обращения (ticket_links). Пересечение окон на одном активе/сервисе проверяет код при планировании:
-- без явного подтверждения — отказ с перечнем конфликтов, с подтверждением — отметка в журнале.
CREATE TABLE itsm.change_windows (
 tenant_id uuid NOT NULL,
 ticket_id uuid NOT NULL,
 starts_at timestamptz NOT NULL,
 ends_at timestamptz NOT NULL,
 risk text NOT NULL CHECK (risk IN ('low','medium','high')),
 plan text NOT NULL CHECK (length(plan) BETWEEN 1 AND 8000),
 rollback_plan text NOT NULL CHECK (length(rollback_plan) BETWEEN 1 AND 8000),
 conflicts_confirmed boolean NOT NULL DEFAULT false,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, ticket_id),
 CHECK (ends_at > starts_at AND ends_at - starts_at <= interval '31 days'),
 FOREIGN KEY (tenant_id, ticket_id) REFERENCES itsm.tickets (tenant_id, ticket_id) ON DELETE RESTRICT
);
CREATE INDEX change_window_time ON itsm.change_windows (tenant_id, starts_at, ends_at);
ALTER TABLE itsm.ticket_events DROP CONSTRAINT ticket_events_kind_check;
ALTER TABLE itsm.ticket_events ADD CONSTRAINT ticket_events_kind_check CHECK (kind IN ('created','state','assigned','comment','linked','priority','approval','fulfilled','window'));
