-- Owner: sources; C21 (presence policy): узел подсети становится missing только после N подряд ПОЛНЫХ обследований
-- без него (проход с ошибками пропуском не считается); события появления/пропажи/возвращения — доказательство
-- переходов для Web и отчётов. Существующие missing-узлы остаются missing (переход уже был зафиксирован).
ALTER TABLE sources.discovery_hosts
 ADD COLUMN misses int NOT NULL DEFAULT 0 CHECK (misses >= 0),
 ADD COLUMN missing_since timestamptz,
 ADD COLUMN returns int NOT NULL DEFAULT 0 CHECK (returns >= 0);
UPDATE sources.discovery_hosts SET missing_since = last_seen WHERE state = 'missing';

CREATE TABLE sources.discovery_host_events (
 tenant_id uuid NOT NULL,
 network_id uuid NOT NULL,
 ip inet NOT NULL,
 run_id uuid NOT NULL,
 kind text NOT NULL CHECK (kind IN ('appeared','missing','returned')),
 at timestamptz NOT NULL,
 PRIMARY KEY (tenant_id, network_id, ip, run_id, kind),
 FOREIGN KEY (tenant_id, network_id, ip) REFERENCES sources.discovery_hosts (tenant_id, network_id, ip) ON DELETE CASCADE
);
CREATE INDEX discovery_host_events_recent ON sources.discovery_host_events (tenant_id, network_id, at DESC);
