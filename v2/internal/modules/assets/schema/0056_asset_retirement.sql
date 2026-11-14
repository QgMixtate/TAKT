-- Owner: assets; C42 (частично, по решению пользователя 2026-11-14): вывод актива из учёта с причиной и автором.
-- Выведенный актив не показывается в реестре и экспорте, не участвует в свежести; его можно вернуть в учёт.
-- Колонки retired_at и lifecycle_state есть с 0005; здесь — причина, автор и согласованность полей.
ALTER TABLE assets.assets ADD COLUMN retired_reason text CHECK (length(retired_reason) BETWEEN 1 AND 500);
ALTER TABLE assets.assets ADD COLUMN retired_by uuid;
ALTER TABLE assets.assets ADD CONSTRAINT asset_retirement_fields CHECK ((retired_at IS NULL) = (retired_reason IS NULL) AND (retired_at IS NULL) = (retired_by IS NULL));
