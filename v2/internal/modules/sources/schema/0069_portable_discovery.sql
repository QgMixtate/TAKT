-- Owner: sources; C23.04: узлы обследования portable-аудита (найден / собран / доступа нет / без профиля). Актив не
-- создаётся; присутствие (C21) по офлайн-снимку не ведётся. Последний пакет по времени манифеста — действующий.
CREATE TABLE sources.portable_discovery_hosts (
 tenant_id uuid NOT NULL,
 source_id uuid NOT NULL,
 ip inet NOT NULL,
 kind text NOT NULL CHECK (kind IN ('linux_ssh','windows_winrm','network_snmp','unknown')),
 ports integer[] NOT NULL DEFAULT '{}',
 outcome text NOT NULL CHECK (outcome IN ('collected','no_profile','no_access','unreachable','skipped')),
 reason text CHECK (reason ~ '^[A-Z][A-Z0-9_]{1,63}$'),
 profile text CHECK (length(profile) BETWEEN 1 AND 64),
 observation_id uuid,
 package_sha256 text NOT NULL CHECK (package_sha256 ~ '^[0-9a-f]{64}$'),
 seen_at timestamptz NOT NULL,
 PRIMARY KEY (tenant_id, source_id, ip),
 FOREIGN KEY (tenant_id, source_id) REFERENCES sources.sources (tenant_id, source_id) ON DELETE CASCADE
);
CREATE INDEX portable_discovery_hosts_outcome ON sources.portable_discovery_hosts (tenant_id, source_id, outcome);
