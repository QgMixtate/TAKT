-- Owner: warehouse; C45.01 (AC W2-06): инвентаризация места — снимок учёта на начало, ввод факта, закрытие с актом и
-- корректирующими движениями (недостача / излишек). Пока инвентаризация открыта, движения по месту запрещены
-- (C41.03 п. 7). Ненайденный экземпляр — состояние lost (не списан: может найтись, вернуть — приходом/излишком).
ALTER TABLE warehouse.units DROP CONSTRAINT units_state_check;
ALTER TABLE warehouse.units ADD CONSTRAINT units_state_check CHECK (state IN ('in_stock','reserved','issued','installed','in_repair','written_off','lost'));

CREATE TABLE warehouse.inventories (
 tenant_id uuid NOT NULL,
 inventory_id uuid NOT NULL,
 location_id uuid NOT NULL,
 act_no text NOT NULL CHECK (length(act_no) BETWEEN 1 AND 32),
 basis text NOT NULL CHECK (length(basis) BETWEEN 1 AND 256),
 state text NOT NULL CHECK (state IN ('open','closed','cancelled')),
 started_at timestamptz NOT NULL DEFAULT now(),
 started_by text NOT NULL,
 closed_at timestamptz,
 closed_by text,
 shortage_movement uuid,
 surplus_movement uuid,
 PRIMARY KEY (tenant_id, inventory_id),
 UNIQUE (tenant_id, act_no),
 FOREIGN KEY (tenant_id, location_id) REFERENCES warehouse.locations (tenant_id, location_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, shortage_movement) REFERENCES warehouse.movements (tenant_id, movement_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, surplus_movement) REFERENCES warehouse.movements (tenant_id, movement_id) ON DELETE RESTRICT,
 CHECK ((state = 'open') = (closed_at IS NULL))
);
CREATE UNIQUE INDEX inventory_open_location ON warehouse.inventories (tenant_id, location_id) WHERE state = 'open';

-- Снимок учёта на начало: экземпляры на месте и количества.
CREATE TABLE warehouse.inventory_expected (
 tenant_id uuid NOT NULL,
 inventory_id uuid NOT NULL,
 item_id uuid NOT NULL,
 unit_id uuid,
 quantity numeric(14,3) NOT NULL CHECK (quantity >= 0),
 FOREIGN KEY (tenant_id, inventory_id) REFERENCES warehouse.inventories (tenant_id, inventory_id) ON DELETE CASCADE,
 FOREIGN KEY (tenant_id, unit_id) REFERENCES warehouse.units (tenant_id, unit_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX inventory_expected_line ON warehouse.inventory_expected (tenant_id, inventory_id, item_id, COALESCE(unit_id, '00000000-0000-0000-0000-000000000000'::uuid));

-- Факт: найденные серийные номера (по позиции) и посчитанные количества. Ввод заменяется целиком (идемпотентно).
CREATE TABLE warehouse.inventory_counts (
 tenant_id uuid NOT NULL,
 inventory_id uuid NOT NULL,
 item_id uuid NOT NULL,
 serial text CHECK (length(serial) BETWEEN 1 AND 128),
 quantity numeric(14,3) NOT NULL CHECK (quantity >= 0),
 FOREIGN KEY (tenant_id, inventory_id) REFERENCES warehouse.inventories (tenant_id, inventory_id) ON DELETE CASCADE,
 FOREIGN KEY (tenant_id, item_id) REFERENCES warehouse.items (tenant_id, item_id) ON DELETE RESTRICT,
 CHECK (serial IS NULL OR quantity = 1)
);
CREATE UNIQUE INDEX inventory_count_line ON warehouse.inventory_counts (tenant_id, inventory_id, item_id, lower(COALESCE(serial, '')));
