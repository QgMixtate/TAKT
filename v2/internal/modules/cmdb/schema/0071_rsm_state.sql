-- Owner: cmdb; C54.03 — состояние РСМ (светофор) до мониторинга метрик (C55): цвет хоста из свежести
-- инвентаризации, присутствия в подсети (C21), отклонения от эталона компонента и открытых конфликтов сопоставления;
-- подъём цвета по дереву компонент → среда → система → направление → компания. Таблицы — производные агрегаты:
-- пересчитываются фоновой задачей и могут быть удалены/построены заново без потери данных.

CREATE TABLE cmdb.host_states (
 tenant_id uuid NOT NULL,
 asset_uid uuid NOT NULL,
 color text NOT NULL CHECK (color IN ('green','yellow','red','grey')),
 reasons jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(reasons) = 'array'),
 last_inventory_at timestamptz,
 computed_at timestamptz NOT NULL,
 PRIMARY KEY (tenant_id, asset_uid),
 FOREIGN KEY (tenant_id, asset_uid) REFERENCES assets.assets(tenant_id, asset_uid) ON DELETE RESTRICT
);
CREATE INDEX host_state_color ON cmdb.host_states (tenant_id, color);

-- Узел дерева: компонент, среда, система (service_uid), направление, компания (node_id = tenant_id).
-- unassigned — только у компании: действующие активы без действующей привязки («хосты вне систем»).
CREATE TABLE cmdb.node_states (
 tenant_id uuid NOT NULL,
 node_kind text NOT NULL CHECK (node_kind IN ('component','environment','system','direction','tenant')),
 node_id uuid NOT NULL,
 color text NOT NULL CHECK (color IN ('green','yellow','red','grey')),
 hosts int NOT NULL DEFAULT 0 CHECK (hosts >= 0),
 green int NOT NULL DEFAULT 0 CHECK (green >= 0),
 yellow int NOT NULL DEFAULT 0 CHECK (yellow >= 0),
 red int NOT NULL DEFAULT 0 CHECK (red >= 0),
 grey int NOT NULL DEFAULT 0 CHECK (grey >= 0),
 unassigned int NOT NULL DEFAULT 0 CHECK (unassigned >= 0),
 reasons jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(reasons) = 'array'),
 computed_at timestamptz NOT NULL,
 PRIMARY KEY (tenant_id, node_kind, node_id),
 FOREIGN KEY (tenant_id) REFERENCES access.tenants(tenant_id) ON DELETE RESTRICT
);
CREATE INDEX node_state_color ON cmdb.node_states (tenant_id, node_kind, color);
