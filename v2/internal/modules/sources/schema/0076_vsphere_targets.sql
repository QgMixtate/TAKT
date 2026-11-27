-- Owner: sources; C57.03 (решение пользователя 25.11 и 27.11): цель сбора «vSphere» — API vCenter или отдельного ESXi
-- (443) только на чтение. Для такой цели центр не регистрирует источник-агент: collector шлёт только снимок платформы
-- C57 от своего имени. Проверка сервера — как у WinRM: PEM CA администратора с именем сервера (admin) или отпечаток
-- сертификата, запомненный при первом подключении (first_use); «CA домена» и Kerberos — только для WinRM.
ALTER TABLE sources.collect_credentials DROP CONSTRAINT collect_credentials_kind_check;
ALTER TABLE sources.collect_credentials ADD CONSTRAINT collect_credentials_kind_check CHECK (kind IN ('ssh','winrm','snmp','vsphere'));
ALTER TABLE sources.remote_targets DROP CONSTRAINT remote_targets_kind_check;
ALTER TABLE sources.remote_targets ADD CONSTRAINT remote_targets_kind_check CHECK (kind IN ('ssh','winrm','snmp','vsphere'));
ALTER TABLE sources.remote_targets DROP CONSTRAINT remote_target_tls_trust;
ALTER TABLE sources.remote_targets ADD CONSTRAINT remote_target_tls_trust CHECK (
 kind NOT IN ('winrm','vsphere') AND tls_ca_pem IS NULL AND tls_cert_sha256 IS NULL AND tls_cert_origin IS NULL
 OR kind IN ('winrm','vsphere') AND tls_ca_pem IS NOT NULL AND tls_server_name IS NOT NULL AND tls_cert_origin = 'admin' AND tls_cert_sha256 IS NULL
 OR kind = 'winrm' AND tls_ca_pem IS NULL AND tls_server_name IS NOT NULL AND tls_cert_origin = 'domain_ca' AND tls_cert_sha256 IS NULL
 OR kind IN ('winrm','vsphere') AND tls_ca_pem IS NULL AND (tls_cert_sha256 IS NULL) = (tls_cert_origin IS NULL) AND tls_cert_origin IS DISTINCT FROM 'admin' AND tls_cert_origin IS DISTINCT FROM 'domain_ca');
ALTER TABLE sources.remote_targets ADD CONSTRAINT remote_target_vsphere_no_agent CHECK (kind <> 'vsphere' OR agent_source_id IS NULL);
