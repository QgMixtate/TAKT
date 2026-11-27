-- Owner: sources; C57.03 (решение пользователя 27.11: zVirt/oVirt после vSphere): цель сбора «oVirt / zVirt» — REST API
-- engine (443) только на чтение. Как у vSphere: источник-агент не регистрируется (снимок платформы от collector),
-- проверка сервера — PEM CA администратора с именем сервера или отпечаток, запомненный при первом подключении.
ALTER TABLE sources.collect_credentials DROP CONSTRAINT collect_credentials_kind_check;
ALTER TABLE sources.collect_credentials ADD CONSTRAINT collect_credentials_kind_check CHECK (kind IN ('ssh','winrm','snmp','vsphere','ovirt'));
ALTER TABLE sources.remote_targets DROP CONSTRAINT remote_targets_kind_check;
ALTER TABLE sources.remote_targets ADD CONSTRAINT remote_targets_kind_check CHECK (kind IN ('ssh','winrm','snmp','vsphere','ovirt'));
ALTER TABLE sources.remote_targets DROP CONSTRAINT remote_target_tls_trust;
ALTER TABLE sources.remote_targets ADD CONSTRAINT remote_target_tls_trust CHECK (
 kind NOT IN ('winrm','vsphere','ovirt') AND tls_ca_pem IS NULL AND tls_cert_sha256 IS NULL AND tls_cert_origin IS NULL
 OR kind IN ('winrm','vsphere','ovirt') AND tls_ca_pem IS NOT NULL AND tls_server_name IS NOT NULL AND tls_cert_origin = 'admin' AND tls_cert_sha256 IS NULL
 OR kind = 'winrm' AND tls_ca_pem IS NULL AND tls_server_name IS NOT NULL AND tls_cert_origin = 'domain_ca' AND tls_cert_sha256 IS NULL
 OR kind IN ('winrm','vsphere','ovirt') AND tls_ca_pem IS NULL AND (tls_cert_sha256 IS NULL) = (tls_cert_origin IS NULL) AND tls_cert_origin IS DISTINCT FROM 'admin' AND tls_cert_origin IS DISTINCT FROM 'domain_ca');
ALTER TABLE sources.remote_targets DROP CONSTRAINT remote_target_vsphere_no_agent;
ALTER TABLE sources.remote_targets ADD CONSTRAINT remote_target_platform_no_agent CHECK (kind NOT IN ('vsphere','ovirt') OR agent_source_id IS NULL);
