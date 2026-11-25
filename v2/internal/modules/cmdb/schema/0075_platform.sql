-- Owner: cmdb; C57.01 — снимки платформ (виртуализация, BMC, каталоги): экземпляр платформы (vCenter, engine
-- oVirt/zVirt, хост KVM, BMC, домен AD), её объекты (ДЦ, кластеры, хосты, ВМ, хранилища, сети) и связи между ними.
-- Снимок присылает collector площадки (подпись ключом collector, отдельно от C03). Объект-хост сопоставляется с
-- активом реестра по BIOS UUID (VMware — обе формы порядка байт) или серийному номеру. Полный снимок без объекта —
-- счётчик пропусков; после 3 полных снимков подряд объект «удалён из платформы».

CREATE TABLE cmdb.platform_instances (
 tenant_id uuid NOT NULL,
 instance_id uuid NOT NULL,
 platform text NOT NULL CHECK (platform IN ('kvm','vsphere','ovirt','redfish','ad','hyperv','proxmox')),
 instance_key text NOT NULL CHECK (length(instance_key) BETWEEN 1 AND 256),
 name text NOT NULL DEFAULT '',
 source_id uuid NOT NULL,
 target_id uuid,
 last_snapshot_at timestamptz,
 last_complete_at timestamptz,
 errors jsonb NOT NULL DEFAULT '[]'::jsonb,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, instance_id),
 UNIQUE (tenant_id, platform, instance_key)
);

CREATE TABLE cmdb.platform_snapshots (
 tenant_id uuid NOT NULL,
 snapshot_id uuid NOT NULL,
 instance_id uuid NOT NULL,
 collected_at timestamptz NOT NULL,
 complete boolean NOT NULL,
 objects integer NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, snapshot_id),
 FOREIGN KEY (tenant_id, instance_id) REFERENCES cmdb.platform_instances (tenant_id, instance_id)
);
CREATE INDEX platform_snapshots_instance ON cmdb.platform_snapshots (tenant_id, instance_id, received_at DESC);

CREATE TABLE cmdb.platform_objects (
 tenant_id uuid NOT NULL,
 instance_id uuid NOT NULL,
 ref text NOT NULL CHECK (length(ref) BETWEEN 1 AND 256),
 kind text NOT NULL CHECK (kind IN ('datacenter','cluster','host','vm','datastore','network','pool','chassis','bmc','computer')),
 name text NOT NULL DEFAULT '',
 bios_uuid text,
 serial text,
 hostname text,
 macs text[] NOT NULL DEFAULT '{}',
 attrs jsonb NOT NULL DEFAULT '{}'::jsonb,
 asset_uid uuid,
 first_seen timestamptz NOT NULL,
 last_seen timestamptz NOT NULL,
 missing_snapshots integer NOT NULL DEFAULT 0 CHECK (missing_snapshots >= 0),
 removed_at timestamptz,
 PRIMARY KEY (tenant_id, instance_id, ref),
 FOREIGN KEY (tenant_id, instance_id) REFERENCES cmdb.platform_instances (tenant_id, instance_id)
);
CREATE INDEX platform_objects_asset ON cmdb.platform_objects (tenant_id, asset_uid) WHERE asset_uid IS NOT NULL;
CREATE INDEX platform_objects_kind ON cmdb.platform_objects (tenant_id, instance_id, kind);

CREATE TABLE cmdb.platform_relations (
 tenant_id uuid NOT NULL,
 instance_id uuid NOT NULL,
 from_ref text NOT NULL,
 rel_type text NOT NULL CHECK (rel_type IN ('runs_on','member_of','uses_storage','connected_to','located_in','managed_by')),
 to_ref text NOT NULL,
 last_seen timestamptz NOT NULL,
 PRIMARY KEY (tenant_id, instance_id, from_ref, rel_type, to_ref),
 FOREIGN KEY (tenant_id, instance_id) REFERENCES cmdb.platform_instances (tenant_id, instance_id)
);
CREATE INDEX platform_relations_to ON cmdb.platform_relations (tenant_id, instance_id, to_ref);
