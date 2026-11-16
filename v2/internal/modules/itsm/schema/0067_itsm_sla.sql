-- Owner: itsm; C50.01 (AC W3-07): простые SLA — один календарь рабочих часов организации (без праздников), сроки
-- реакции и решения по виду (инцидент/заявка) и приоритету в рабочих минутах, таймеры обращения с паузами
-- («ждём заявителя», «на согласовании»), отметки предупреждения и нарушения. Нет строки — действуют значения по умолчанию.
CREATE TABLE itsm.business_hours (
 tenant_id uuid NOT NULL PRIMARY KEY,
 timezone text NOT NULL CHECK (length(timezone) BETWEEN 1 AND 64),
 days smallint[] NOT NULL CHECK (cardinality(days) BETWEEN 1 AND 7 AND days <@ ARRAY[1,2,3,4,5,6,7]::smallint[]),
 start_minute smallint NOT NULL CHECK (start_minute BETWEEN 0 AND 1439),
 end_minute smallint NOT NULL CHECK (end_minute BETWEEN 1 AND 1440),
 warn_percent smallint NOT NULL DEFAULT 80 CHECK (warn_percent BETWEEN 50 AND 99),
 revision platform.uint64 NOT NULL DEFAULT 1,
 CHECK (end_minute > start_minute),
 FOREIGN KEY (tenant_id) REFERENCES access.tenants (tenant_id) ON DELETE RESTRICT
);

CREATE TABLE itsm.sla_policies (
 tenant_id uuid NOT NULL,
 kind text NOT NULL CHECK (kind IN ('incident','request')),
 priority smallint NOT NULL CHECK (priority BETWEEN 1 AND 4),
 response_minutes integer NOT NULL CHECK (response_minutes BETWEEN 1 AND 100000),
 resolution_minutes integer NOT NULL CHECK (resolution_minutes BETWEEN 1 AND 1000000),
 PRIMARY KEY (tenant_id, kind, priority),
 CHECK (resolution_minutes >= response_minutes),
 FOREIGN KEY (tenant_id) REFERENCES access.tenants (tenant_id) ON DELETE RESTRICT
);

-- Таймер: прошедшее рабочее время = рабочие минуты [started_at, stopped_at|now] − paused_minutes − текущая пауза.
CREATE TABLE itsm.sla_timers (
 tenant_id uuid NOT NULL,
 ticket_id uuid NOT NULL,
 metric text NOT NULL CHECK (metric IN ('response','resolution')),
 target_minutes integer NOT NULL CHECK (target_minutes > 0),
 started_at timestamptz NOT NULL,
 stopped_at timestamptz,
 paused_since timestamptz,
 paused_minutes double precision NOT NULL DEFAULT 0 CHECK (paused_minutes >= 0),
 warned_at timestamptz,
 breached_at timestamptz,
 PRIMARY KEY (tenant_id, ticket_id, metric),
 FOREIGN KEY (tenant_id, ticket_id) REFERENCES itsm.tickets (tenant_id, ticket_id) ON DELETE RESTRICT
);
CREATE INDEX sla_timer_running ON itsm.sla_timers (tenant_id) WHERE stopped_at IS NULL AND breached_at IS NULL;
ALTER TABLE itsm.ticket_events DROP CONSTRAINT ticket_events_kind_check;
ALTER TABLE itsm.ticket_events ADD CONSTRAINT ticket_events_kind_check CHECK (kind IN ('created','state','assigned','comment','linked','priority','approval','fulfilled','window','sla'));
