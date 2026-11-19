-- Owner: cmdb; C53.02 — для экрана «Системы»: число хостов с актуальными данными (инвентаризация не старше суток) и
-- разбивка проблем по видам (устарели, нет данных, пропали, не по эталону, конфликт сопоставления) в каждом узле.
-- Производные агрегаты: пересчитываются фоновой задачей C54.03.
ALTER TABLE cmdb.node_states
 ADD COLUMN fresh int NOT NULL DEFAULT 0 CHECK (fresh >= 0),
 ADD COLUMN problems jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(problems) = 'object');
