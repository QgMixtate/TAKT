-- Owner: cmdb; C53.03 — поля карточек по макетам C53-mockups/7–8: роль компонента («кластер серверов 1С»),
-- дежурные (текст: «Группа приложений, неделя 47») и резервный ответственный системы (субъект responsibility).
ALTER TABLE cmdb.components ADD COLUMN role text CHECK (length(role) <= 256);
ALTER TABLE cmdb.services
 ADD COLUMN on_call text CHECK (length(on_call) <= 256),
 ADD COLUMN backup_subject_id uuid,
 ADD FOREIGN KEY (tenant_id, backup_subject_id) REFERENCES responsibility.subjects(tenant_id, subject_id) ON DELETE RESTRICT;
