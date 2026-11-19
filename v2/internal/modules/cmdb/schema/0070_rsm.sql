-- Owner: cmdb; C54.01 — ресурсно-сервисная модель: направление → система (= сервис C26) → среда → компонент → хост.
-- Только дописывание: сервисы C26 становятся системами с теми же service_uid; связи C26 (depends_on/uses между
-- системами) не меняются. Межтенантные ссылки невозможны: все FK идут по (tenant_id, …).

CREATE TABLE cmdb.directions (
 tenant_id uuid NOT NULL,
 direction_uid uuid NOT NULL,
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
 revision platform.uint64 NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(),
 retired_at timestamptz,
 PRIMARY KEY (tenant_id, direction_uid),
 UNIQUE (direction_uid),
 FOREIGN KEY (tenant_id) REFERENCES access.tenants(tenant_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX direction_active_name ON cmdb.directions (tenant_id, lower(name)) WHERE retired_at IS NULL;

-- Система: поля поверх сервиса C26. Владелец от бизнеса — текст (организационная единица); ответственный ИТ — субъект
-- модуля responsibility (команда или человек). Площадки системы не хранятся: вычисляются по площадкам её хостов.
ALTER TABLE cmdb.services
 ADD COLUMN direction_uid uuid,
 ADD COLUMN business_owner text CHECK (length(business_owner) <= 512),
 ADD COLUMN it_subject_id uuid,
 ADD COLUMN maintenance_window text CHECK (length(maintenance_window) <= 256),
 ADD FOREIGN KEY (tenant_id, direction_uid) REFERENCES cmdb.directions(tenant_id, direction_uid) ON DELETE RESTRICT,
 ADD FOREIGN KEY (tenant_id, it_subject_id) REFERENCES responsibility.subjects(tenant_id, subject_id) ON DELETE RESTRICT;
CREATE INDEX service_direction ON cmdb.services (tenant_id, direction_uid) WHERE direction_uid IS NOT NULL;

CREATE TABLE cmdb.environments (
 tenant_id uuid NOT NULL,
 environment_id uuid NOT NULL,
 service_uid uuid NOT NULL,
 kind text NOT NULL CHECK (kind IN ('prod','test','dev','stage','dr','other')),
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
 revision platform.uint64 NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(),
 retired_at timestamptz,
 PRIMARY KEY (tenant_id, environment_id),
 UNIQUE (environment_id),
 FOREIGN KEY (tenant_id, service_uid) REFERENCES cmdb.services(tenant_id, service_uid) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX environment_active_name ON cmdb.environments (tenant_id, service_uid, lower(name)) WHERE retired_at IS NULL;

-- Компонент (роль) в среде; эталон — ожидаемые ОС, версии ПО, антивирус, порты, локальные админы (вариативно → JSONB).
CREATE TABLE cmdb.components (
 tenant_id uuid NOT NULL,
 component_id uuid NOT NULL,
 environment_id uuid NOT NULL,
 name text NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
 critical boolean NOT NULL DEFAULT false,
 baseline jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(baseline) = 'object' AND octet_length(baseline::text) <= 65536),
 revision platform.uint64 NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(),
 retired_at timestamptz,
 PRIMARY KEY (tenant_id, component_id),
 UNIQUE (component_id),
 FOREIGN KEY (tenant_id, environment_id) REFERENCES cmdb.environments(tenant_id, environment_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX component_active_name ON cmdb.components (tenant_id, environment_id, lower(name)) WHERE retired_at IS NULL;

-- Правило автопривязки хостов к компоненту; mode: propose — предложение оператору, auto — сразу.
CREATE TABLE cmdb.binding_rules (
 tenant_id uuid NOT NULL,
 rule_id uuid NOT NULL,
 component_id uuid NOT NULL,
 kind text NOT NULL CHECK (kind IN ('subnet','hostname_glob','ad_ou','software','asset_class')),
 pattern text NOT NULL CHECK (length(pattern) BETWEEN 1 AND 512),
 mode text NOT NULL DEFAULT 'propose' CHECK (mode IN ('propose','auto')),
 enabled boolean NOT NULL DEFAULT true,
 revision platform.uint64 NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(),
 retired_at timestamptz,
 PRIMARY KEY (tenant_id, rule_id),
 UNIQUE (rule_id),
 FOREIGN KEY (tenant_id, component_id) REFERENCES cmdb.components(tenant_id, component_id) ON DELETE RESTRICT
);
CREATE INDEX binding_rule_component ON cmdb.binding_rules (tenant_id, component_id) WHERE retired_at IS NULL;

-- Привязка хоста к компоненту. Хост может входить в несколько компонентов/систем («общий»); у хоста не больше одной
-- основной действующей привязки. proposed — предложение правила, ждёт подтверждения оператора.
CREATE TABLE cmdb.bindings (
 tenant_id uuid NOT NULL,
 binding_id uuid NOT NULL,
 component_id uuid NOT NULL,
 asset_uid uuid NOT NULL,
 status text NOT NULL CHECK (status IN ('active','proposed','rejected')),
 is_primary boolean NOT NULL DEFAULT false,
 origin text NOT NULL CHECK (origin IN ('manual','import','rule')),
 rule_id uuid,
 valid_from timestamptz NOT NULL DEFAULT now(),
 valid_to timestamptz,
 actor_ref text NOT NULL,
 PRIMARY KEY (tenant_id, binding_id),
 FOREIGN KEY (tenant_id, component_id) REFERENCES cmdb.components(tenant_id, component_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, asset_uid) REFERENCES assets.assets(tenant_id, asset_uid) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, rule_id) REFERENCES cmdb.binding_rules(tenant_id, rule_id) ON DELETE RESTRICT,
 CHECK (origin <> 'rule' OR rule_id IS NOT NULL),
 CHECK (status = 'active' OR NOT is_primary),
 CHECK (valid_to IS NULL OR valid_to >= valid_from)
);
CREATE UNIQUE INDEX binding_open_pair ON cmdb.bindings (tenant_id, component_id, asset_uid) WHERE valid_to IS NULL AND status <> 'rejected';
CREATE UNIQUE INDEX binding_one_primary ON cmdb.bindings (tenant_id, asset_uid) WHERE valid_to IS NULL AND is_primary;
CREATE INDEX binding_asset ON cmdb.bindings (tenant_id, asset_uid) WHERE valid_to IS NULL;
CREATE INDEX binding_component ON cmdb.bindings (tenant_id, component_id) WHERE valid_to IS NULL;

-- Зависимость компонент → компонент (между системами — по-прежнему cmdb.relations depends_on/uses между сервисами).
CREATE TABLE cmdb.component_dependencies (
 tenant_id uuid NOT NULL,
 dependency_id uuid NOT NULL,
 from_component_id uuid NOT NULL,
 to_component_id uuid NOT NULL,
 valid_from timestamptz NOT NULL DEFAULT now(),
 valid_to timestamptz,
 actor_ref text NOT NULL,
 PRIMARY KEY (tenant_id, dependency_id),
 FOREIGN KEY (tenant_id, from_component_id) REFERENCES cmdb.components(tenant_id, component_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, to_component_id) REFERENCES cmdb.components(tenant_id, component_id) ON DELETE RESTRICT,
 CHECK (from_component_id <> to_component_id),
 CHECK (valid_to IS NULL OR valid_to >= valid_from)
);
CREATE UNIQUE INDEX component_dependency_open ON cmdb.component_dependencies (tenant_id, from_component_id, to_component_id) WHERE valid_to IS NULL;

-- История модуля: новые объекты и действия РСМ.
ALTER TABLE cmdb.changes DROP CONSTRAINT changes_object_type_check;
ALTER TABLE cmdb.changes ADD CONSTRAINT changes_object_type_check CHECK (object_type IN
 ('service','relation','direction','environment','component','binding','binding_rule','component_dependency'));
ALTER TABLE cmdb.changes DROP CONSTRAINT changes_action_check;
ALTER TABLE cmdb.changes ADD CONSTRAINT changes_action_check CHECK (action IN
 ('created','updated','retired','retargeted','proposed','confirmed','rejected','closed'));
