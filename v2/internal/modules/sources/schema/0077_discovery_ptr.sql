-- Owner: sources; C57.03: имя найденного узла по обратному DNS (PTR) — collector спрашивает свой DNS-сервер после
-- обследования подсети. Хранится последнее полученное имя: обследование без ответа DNS имя не стирает.
ALTER TABLE sources.discovery_hosts ADD COLUMN ptr_name text CHECK (length(ptr_name) BETWEEN 1 AND 253);
