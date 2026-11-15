-- Owner: warehouse; волна 2 (C43.01–C43.02, C42.02): места, каталог, серийные экземпляры, остатки, резервы, журнал
-- движений и номера актов. Инварианты C41.03: нет двойной выдачи (одно состояние/держатель у экземпляра), нет
-- отрицательного остатка (CHECK), журнал движений только дописывается (исправление — сторно), финансов нет.
CREATE SCHEMA IF NOT EXISTS warehouse;

CREATE TABLE warehouse.locations (
 tenant_id uuid NOT NULL,
 location_id uuid NOT NULL,
 site_id uuid NOT NULL,
 parent_id uuid,
 kind text NOT NULL CHECK (kind IN ('warehouse','bin','repair')),
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
 active boolean NOT NULL DEFAULT true,
 PRIMARY KEY (tenant_id, location_id),
 FOREIGN KEY (tenant_id, site_id) REFERENCES scope.sites (tenant_id, site_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, parent_id) REFERENCES warehouse.locations (tenant_id, location_id) ON DELETE RESTRICT,
 CHECK (parent_id IS DISTINCT FROM location_id),
 CHECK ((kind = 'bin') = (parent_id IS NOT NULL))
);
CREATE UNIQUE INDEX location_name ON warehouse.locations (tenant_id, COALESCE(parent_id, site_id), lower(name));

CREATE TABLE warehouse.items (
 tenant_id uuid NOT NULL,
 item_id uuid NOT NULL,
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
 kind text NOT NULL CHECK (kind IN ('serial','quantity')),
 unit text NOT NULL DEFAULT 'шт' CHECK (length(unit) BETWEEN 1 AND 16),
 category text CHECK (length(category) <= 64),
 active boolean NOT NULL DEFAULT true,
 PRIMARY KEY (tenant_id, item_id),
 FOREIGN KEY (tenant_id) REFERENCES access.tenants (tenant_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX item_name ON warehouse.items (tenant_id, lower(name));

-- Серийный экземпляр: ровно одно место ИЛИ один держатель ИЛИ актив, на который установлен; списанный — нигде.
CREATE TABLE warehouse.units (
 tenant_id uuid NOT NULL,
 unit_id uuid NOT NULL,
 item_id uuid NOT NULL,
 serial text NOT NULL CHECK (length(serial) BETWEEN 1 AND 128),
 inventory_no text CHECK (length(inventory_no) BETWEEN 1 AND 64),
 asset_uid uuid,
 state text NOT NULL CHECK (state IN ('in_stock','reserved','issued','installed','in_repair','written_off')),
 location_id uuid,
 holder_id uuid,
 installed_on uuid,
 revision platform.uint64 NOT NULL DEFAULT 1,
 PRIMARY KEY (tenant_id, unit_id),
 FOREIGN KEY (tenant_id, item_id) REFERENCES warehouse.items (tenant_id, item_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, location_id) REFERENCES warehouse.locations (tenant_id, location_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, holder_id) REFERENCES responsibility.subjects (tenant_id, subject_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, asset_uid) REFERENCES assets.assets (tenant_id, asset_uid) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, installed_on) REFERENCES assets.assets (tenant_id, asset_uid) ON DELETE RESTRICT,
 CHECK (CASE state
  WHEN 'in_stock' THEN location_id IS NOT NULL AND holder_id IS NULL AND installed_on IS NULL
  WHEN 'reserved' THEN location_id IS NOT NULL AND holder_id IS NULL AND installed_on IS NULL
  WHEN 'in_repair' THEN location_id IS NOT NULL AND holder_id IS NULL AND installed_on IS NULL
  WHEN 'issued' THEN location_id IS NULL AND holder_id IS NOT NULL AND installed_on IS NULL
  WHEN 'installed' THEN location_id IS NULL AND holder_id IS NULL AND installed_on IS NOT NULL
  ELSE location_id IS NULL AND holder_id IS NULL AND installed_on IS NULL END),
 CHECK (installed_on IS DISTINCT FROM asset_uid OR installed_on IS NULL)
);
CREATE UNIQUE INDEX unit_serial ON warehouse.units (tenant_id, item_id, lower(serial));
CREATE UNIQUE INDEX unit_inventory_no ON warehouse.units (tenant_id, lower(inventory_no)) WHERE inventory_no IS NOT NULL;
CREATE UNIQUE INDEX unit_asset ON warehouse.units (tenant_id, asset_uid) WHERE asset_uid IS NOT NULL;
CREATE INDEX unit_holder ON warehouse.units (tenant_id, holder_id) WHERE holder_id IS NOT NULL;
CREATE INDEX unit_installed ON warehouse.units (tenant_id, installed_on) WHERE installed_on IS NOT NULL;

-- Остаток количественной позиции по месту (проекция журнала движений; пересчёт из движений = этой таблице).
CREATE TABLE warehouse.stock (
 tenant_id uuid NOT NULL,
 item_id uuid NOT NULL,
 location_id uuid NOT NULL,
 quantity numeric(14,3) NOT NULL CHECK (quantity >= 0),
 reserved numeric(14,3) NOT NULL DEFAULT 0 CHECK (reserved >= 0 AND reserved <= quantity),
 PRIMARY KEY (tenant_id, item_id, location_id),
 FOREIGN KEY (tenant_id, item_id) REFERENCES warehouse.items (tenant_id, item_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, location_id) REFERENCES warehouse.locations (tenant_id, location_id) ON DELETE RESTRICT
);

CREATE TABLE warehouse.reservations (
 tenant_id uuid NOT NULL,
 reservation_id uuid NOT NULL,
 unit_id uuid,
 item_id uuid,
 location_id uuid,
 quantity numeric(14,3) CHECK (quantity > 0),
 holder_id uuid NOT NULL,
 basis text NOT NULL CHECK (length(basis) BETWEEN 1 AND 256),
 expires_at timestamptz NOT NULL,
 state text NOT NULL CHECK (state IN ('active','fulfilled','cancelled','expired')),
 created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, reservation_id),
 FOREIGN KEY (tenant_id, unit_id) REFERENCES warehouse.units (tenant_id, unit_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, item_id, location_id) REFERENCES warehouse.stock (tenant_id, item_id, location_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, holder_id) REFERENCES responsibility.subjects (tenant_id, subject_id) ON DELETE RESTRICT,
 CHECK ((unit_id IS NULL) = (item_id IS NOT NULL AND location_id IS NOT NULL AND quantity IS NOT NULL))
);
CREATE UNIQUE INDEX reservation_unit_active ON warehouse.reservations (tenant_id, unit_id) WHERE state = 'active' AND unit_id IS NOT NULL;
CREATE INDEX reservation_expiry ON warehouse.reservations (expires_at) WHERE state = 'active';

-- Номер акта: сквозной по организации и году (выдаётся в транзакции движения).
CREATE TABLE warehouse.act_counters (
 tenant_id uuid NOT NULL,
 year int NOT NULL CHECK (year BETWEEN 2000 AND 9999),
 last int NOT NULL CHECK (last > 0),
 PRIMARY KEY (tenant_id, year)
);

-- Журнал движений: одна операция = одна запись и её строки. Только дописывается (без UPDATE/DELETE в коде).
CREATE TABLE warehouse.movements (
 tenant_id uuid NOT NULL,
 movement_id uuid NOT NULL,
 kind text NOT NULL CHECK (kind IN ('receive','issue','return','transfer','repair_out','repair_in','install','remove','write_off','adjust','reverse')),
 act_no text NOT NULL CHECK (length(act_no) BETWEEN 1 AND 32),
 occurred_at timestamptz NOT NULL DEFAULT now(),
 actor_ref text NOT NULL,
 basis text NOT NULL CHECK (length(basis) BETWEEN 1 AND 256),
 note text CHECK (length(note) <= 1024),
 from_location uuid, to_location uuid,
 from_holder uuid, to_holder uuid,
 asset_uid uuid,
 reverses uuid,
 PRIMARY KEY (tenant_id, movement_id),
 UNIQUE (tenant_id, act_no),
 FOREIGN KEY (tenant_id, from_location) REFERENCES warehouse.locations (tenant_id, location_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, to_location) REFERENCES warehouse.locations (tenant_id, location_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, from_holder) REFERENCES responsibility.subjects (tenant_id, subject_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, to_holder) REFERENCES responsibility.subjects (tenant_id, subject_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, asset_uid) REFERENCES assets.assets (tenant_id, asset_uid) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, reverses) REFERENCES warehouse.movements (tenant_id, movement_id) ON DELETE RESTRICT
);
CREATE INDEX movement_recent ON warehouse.movements (tenant_id, occurred_at DESC);
CREATE UNIQUE INDEX movement_reversed_once ON warehouse.movements (tenant_id, reverses) WHERE reverses IS NOT NULL;

CREATE TABLE warehouse.movement_lines (
 tenant_id uuid NOT NULL,
 movement_id uuid NOT NULL,
 line_no int NOT NULL CHECK (line_no BETWEEN 1 AND 500),
 item_id uuid NOT NULL,
 unit_id uuid,
 quantity numeric(14,3) NOT NULL CHECK (quantity > 0),
 PRIMARY KEY (tenant_id, movement_id, line_no),
 FOREIGN KEY (tenant_id, movement_id) REFERENCES warehouse.movements (tenant_id, movement_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, item_id) REFERENCES warehouse.items (tenant_id, item_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, unit_id) REFERENCES warehouse.units (tenant_id, unit_id) ON DELETE RESTRICT,
 CHECK (unit_id IS NULL OR quantity = 1)
);
CREATE INDEX movement_line_unit ON warehouse.movement_lines (tenant_id, unit_id) WHERE unit_id IS NOT NULL;

-- Журнал только дописывается: изменение и удаление движений запрещены на уровне БД.
CREATE FUNCTION warehouse.movements_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'warehouse movements are append-only' USING ERRCODE = 'P0001'; END $$;
CREATE TRIGGER movements_append_only BEFORE UPDATE OR DELETE ON warehouse.movements FOR EACH ROW EXECUTE FUNCTION warehouse.movements_append_only();
CREATE TRIGGER movement_lines_append_only BEFORE UPDATE OR DELETE ON warehouse.movement_lines FOR EACH ROW EXECUTE FUNCTION warehouse.movements_append_only();
