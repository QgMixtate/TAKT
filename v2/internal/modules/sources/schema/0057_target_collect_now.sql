-- Owner: sources; стенд, задание №12 (дефект 5): «Собрать сейчас» у цели сбора — время запроса; collector при
-- следующем опросе целей (раз в минуту) видит новое значение и запускает сбор цели сразу.
ALTER TABLE sources.remote_targets ADD COLUMN collect_requested_at timestamptz;
