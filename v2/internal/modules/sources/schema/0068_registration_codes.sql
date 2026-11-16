-- Owner: sources; C52.01: коды регистрации — установка агента/collector «скачал → ввёл код». Код показывается один
-- раз, хранится только SHA-256; привязан к площадке (агент — ещё и к collector), сроку и числу установок. По коду центр
-- сам создаёт источник и grant под CSR устанавливаемой машины (закрытый ключ не покидает её).
CREATE TABLE sources.registration_codes (
 tenant_id uuid NOT NULL,
 code_id uuid NOT NULL,
 code_hash text NOT NULL UNIQUE CHECK (code_hash ~ '^[0-9a-f]{64}$'),
 source_kind text NOT NULL CHECK (source_kind IN ('agent','collector')),
 site_id uuid NOT NULL,
 collector_id uuid,
 inventory_platform text,
 max_uses integer NOT NULL CHECK (max_uses BETWEEN 1 AND 10000),
 used integer NOT NULL DEFAULT 0 CHECK (used >= 0),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 comment text NOT NULL DEFAULT '' CHECK (length(comment) <= 256),
 created_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, code_id),
 CHECK (used <= max_uses),
 CHECK ((source_kind = 'agent') = (collector_id IS NOT NULL)),
 FOREIGN KEY (tenant_id, collector_id) REFERENCES sources.collectors (tenant_id, collector_id) ON DELETE RESTRICT
);
CREATE INDEX registration_code_list ON sources.registration_codes (tenant_id, created_at DESC);

-- Установка по коду: одна строка на источник; повтор того же CSR по тому же коду не создаёт второй источник.
CREATE TABLE sources.registration_uses (
 tenant_id uuid NOT NULL,
 code_id uuid NOT NULL,
 source_id uuid NOT NULL,
 csr_sha256 text NOT NULL CHECK (csr_sha256 ~ '^[0-9a-f]{64}$'),
 hostname text NOT NULL CHECK (length(hostname) BETWEEN 1 AND 255),
 registered_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, code_id, source_id),
 UNIQUE (tenant_id, code_id, csr_sha256),
 FOREIGN KEY (tenant_id, code_id) REFERENCES sources.registration_codes (tenant_id, code_id) ON DELETE RESTRICT,
 FOREIGN KEY (tenant_id, source_id) REFERENCES sources.sources (tenant_id, source_id) ON DELETE RESTRICT
);
