-- Owner: itsm; волна 3 (C46.02–C46.03, C47.01–C47.02): обращения четырёх видов, номер по виду и году, приоритет из
-- влияния и срочности, состояние (переходы проверяет код по таблице процесса), исполнитель и команда, ревизия для
-- конкурентного назначения; журнал обращения только дописывается; связи с активом/сервисом/обращением/движением склада.
CREATE SCHEMA IF NOT EXISTS itsm;

CREATE TABLE itsm.tickets (
 tenant_id uuid NOT NULL,
 ticket_id uuid NOT NULL,
 kind text NOT NULL CHECK (kind IN ('incident','request','change','problem')),
 number text NOT NULL CHECK (number ~ '^(INC|REQ|CHG|PRB)-[0-9]{4}-[0-9]{6}$'),
 title text NOT NULL CHECK (length(title) BETWEEN 1 AND 256),
 description text NOT NULL DEFAULT '' CHECK (length(description) <= 8000),
 impact smallint NOT NULL CHECK (impact BETWEEN 1 AND 3),
 urgency smallint NOT NULL CHECK (urgency BETWEEN 1 AND 3),
 priority smallint NOT NULL CHECK (priority BETWEEN 1 AND 4),
 state text NOT NULL CHECK (length(state) BETWEEN 1 AND 32),
 requester_id uuid,
 assignee_id uuid,
 team_id uuid,
 resolution text CHECK (length(resolution) <= 4000),
 workaround text CHECK (length(workaround) <= 4000),
 reopen_count int NOT NULL DEFAULT 0 CHECK (reopen_count >= 0),
 created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 resolved_at timestamptz,
 closed_at timestamptz,
 revision platform.uint64 NOT NULL DEFAULT 1,
 PRIMARY KEY (tenant_id, ticket_id),
 UNIQUE (tenant_id, number),
 FOREIGN KEY (tenant_id) REFERENCES access.tenants (tenant_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, requester_id) REFERENCES responsibility.subjects (tenant_id, subject_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, assignee_id) REFERENCES responsibility.subjects (tenant_id, subject_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, team_id) REFERENCES responsibility.subjects (tenant_id, subject_id) ON DELETE RESTRICT
);
CREATE INDEX ticket_queue ON itsm.tickets (tenant_id, kind, state, priority, created_at);
CREATE INDEX ticket_assignee ON itsm.tickets (tenant_id, assignee_id) WHERE assignee_id IS NOT NULL;
CREATE INDEX ticket_team ON itsm.tickets (tenant_id, team_id) WHERE team_id IS NOT NULL;
CREATE INDEX ticket_requester ON itsm.tickets (tenant_id, requester_id) WHERE requester_id IS NOT NULL;

CREATE TABLE itsm.ticket_counters (
 tenant_id uuid NOT NULL,
 prefix text NOT NULL CHECK (prefix IN ('INC','REQ','CHG','PRB')),
 year int NOT NULL CHECK (year BETWEEN 2000 AND 9999),
 last int NOT NULL CHECK (last > 0),
 PRIMARY KEY (tenant_id, prefix, year)
);

-- Связь обращения: ровно одна цель (актив, сервис, другое обращение, движение склада).
CREATE TABLE itsm.ticket_links (
 tenant_id uuid NOT NULL,
 ticket_id uuid NOT NULL,
 target_kind text NOT NULL CHECK (target_kind IN ('asset','service','ticket','movement')),
 target_id uuid NOT NULL,
 created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, ticket_id, target_kind, target_id),
 FOREIGN KEY (tenant_id, ticket_id) REFERENCES itsm.tickets (tenant_id, ticket_id) ON DELETE RESTRICT
);
CREATE INDEX ticket_link_target ON itsm.ticket_links (tenant_id, target_kind, target_id);

-- Журнал обращения: создание, переходы, назначения, комментарии (public=false — внутренний, заявителю не виден).
CREATE TABLE itsm.ticket_events (
 tenant_id uuid NOT NULL,
 event_id uuid NOT NULL,
 ticket_id uuid NOT NULL,
 kind text NOT NULL CHECK (kind IN ('created','state','assigned','comment','linked','priority')),
 public boolean NOT NULL DEFAULT true,
 detail jsonb NOT NULL DEFAULT '{}'::jsonb,
 text text CHECK (length(text) <= 8000),
 actor_ref text NOT NULL,
 occurred_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, event_id),
 FOREIGN KEY (tenant_id, ticket_id) REFERENCES itsm.tickets (tenant_id, ticket_id) ON DELETE RESTRICT
);
CREATE INDEX ticket_event_feed ON itsm.ticket_events (tenant_id, ticket_id, occurred_at);
CREATE FUNCTION itsm.events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'ticket events are append-only' USING ERRCODE = 'P0001'; END $$;
CREATE TRIGGER ticket_events_append_only BEFORE UPDATE OR DELETE ON itsm.ticket_events FOR EACH ROW EXECUTE FUNCTION itsm.events_append_only();
