-- Owner: itsm; C48 (AC W3-05): каталог услуг и заявки. Услуга — форма полей, видимость, согласование (человек или
-- команда), исполнитель и, для складских услуг, позиция склада (исполнение — выдача экземпляра этой позиции
-- заявителю с актом, в одной транзакции со сменой состояния заявки; повтор не создаёт второй выдачи).
CREATE TABLE itsm.catalog_items (
 tenant_id uuid NOT NULL,
 item_id uuid NOT NULL,
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
 description text NOT NULL DEFAULT '' CHECK (length(description) <= 4000),
 form jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(form) = 'array'),
 approver_id uuid,
 team_id uuid,
 warehouse_item_id uuid,
 active boolean NOT NULL DEFAULT true,
 revision platform.uint64 NOT NULL DEFAULT 1,
 PRIMARY KEY (tenant_id, item_id),
 FOREIGN KEY (tenant_id, approver_id) REFERENCES responsibility.subjects (tenant_id, subject_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, team_id) REFERENCES responsibility.subjects (tenant_id, subject_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, warehouse_item_id) REFERENCES warehouse.items (tenant_id, item_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX catalog_item_name ON itsm.catalog_items (tenant_id, lower(name)) WHERE active;

ALTER TABLE itsm.tickets ADD COLUMN catalog_item_id uuid;
ALTER TABLE itsm.tickets ADD COLUMN form_values jsonb CHECK (form_values IS NULL OR jsonb_typeof(form_values) = 'object');
ALTER TABLE itsm.tickets ADD CONSTRAINT ticket_catalog_item FOREIGN KEY (tenant_id, catalog_item_id) REFERENCES itsm.catalog_items (tenant_id, item_id) ON DELETE RESTRICT;
ALTER TABLE itsm.tickets ADD CONSTRAINT ticket_request_catalog CHECK ((kind = 'request') = (catalog_item_id IS NOT NULL));

-- Решение по согласованию (одно на заявку).
CREATE TABLE itsm.approvals (
 tenant_id uuid NOT NULL,
 ticket_id uuid NOT NULL,
 approver_id uuid,
 decision text NOT NULL CHECK (decision IN ('approved','rejected')),
 comment text CHECK (length(comment) <= 2000),
 decided_by text NOT NULL,
 decided_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, ticket_id),
 FOREIGN KEY (tenant_id, ticket_id) REFERENCES itsm.tickets (tenant_id, ticket_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, approver_id) REFERENCES responsibility.subjects (tenant_id, subject_id) ON DELETE RESTRICT
);
ALTER TABLE itsm.ticket_events DROP CONSTRAINT ticket_events_kind_check;
ALTER TABLE itsm.ticket_events ADD CONSTRAINT ticket_events_kind_check CHECK (kind IN ('created','state','assigned','comment','linked','priority','approval','fulfilled'));
