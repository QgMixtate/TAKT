-- Owner: cmdb; C53.04 — проекция реестра хостов для плотного списка (100 тыс.+): имя, IP, ОС, тип, площадка/сегмент,
-- ответственный и команда, основная система/компонент, полнота разделов, источники, свежесть. Производная таблица:
-- строится фоновой задачей раз в 5 минут и точечно после приёма наблюдения; может быть удалена и построена заново
-- без потери данных. Фильтры, сортировка, счётчики и дерево группировки считаются по ней на сервере.

CREATE TABLE cmdb.host_registry (
 tenant_id uuid NOT NULL,
 asset_uid uuid NOT NULL,
 name text NOT NULL,
 name_key text NOT NULL,
 ip text NOT NULL DEFAULT '',
 os text NOT NULL DEFAULT '',
 os_family text NOT NULL DEFAULT 'unknown' CHECK (os_family IN ('windows','linux','macos','network','other','unknown')),
 asset_class text NOT NULL DEFAULT 'unknown',
 site_id uuid NOT NULL,
 site_name text NOT NULL DEFAULT '',
 segment text NOT NULL DEFAULT '',
 accountable_id uuid,
 accountable_name text NOT NULL DEFAULT '',
 team_name text NOT NULL DEFAULT '',
 site_fallback boolean NOT NULL DEFAULT false,
 system_uid uuid,
 system_name text NOT NULL DEFAULT '',
 component_name text NOT NULL DEFAULT '',
 sections_ok int NOT NULL DEFAULT 0 CHECK (sections_ok >= 0),
 sections_total int NOT NULL DEFAULT 0 CHECK (sections_total >= 0),
 sources text[] NOT NULL DEFAULT '{}',
 freshness text NOT NULL DEFAULT 'unknown' CHECK (freshness IN ('fresh','stale','unknown')),
 last_inventory_at timestamptz,
 created_at timestamptz NOT NULL,
 computed_at timestamptz NOT NULL,
 PRIMARY KEY (tenant_id, asset_uid),
 FOREIGN KEY (tenant_id, asset_uid) REFERENCES assets.assets(tenant_id, asset_uid) ON DELETE RESTRICT
);
CREATE INDEX host_registry_name ON cmdb.host_registry (tenant_id, name_key, asset_uid);
CREATE INDEX host_registry_site ON cmdb.host_registry (tenant_id, site_id, segment);
CREATE INDEX host_registry_os ON cmdb.host_registry (tenant_id, os_family, os);
CREATE INDEX host_registry_owner ON cmdb.host_registry (tenant_id, accountable_id);
CREATE INDEX host_registry_system ON cmdb.host_registry (tenant_id, system_uid);
CREATE INDEX host_registry_inventory ON cmdb.host_registry (tenant_id, last_inventory_at);
