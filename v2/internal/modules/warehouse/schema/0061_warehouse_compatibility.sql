-- Owner: warehouse; C44.01 — совместимость комплектующих: позиция каталога подходит к моделям оборудования (подстрока
-- модели/производителя актива из инвентаризации, без учёта регистра). Нет правил — подходит ко всему. Установка
-- неподходящего — только с явной пометкой «под ответственность» (compat_override), она остаётся в журнале.
CREATE TABLE warehouse.item_compatibility (
 tenant_id uuid NOT NULL,
 item_id uuid NOT NULL,
 model text NOT NULL CHECK (length(model) BETWEEN 2 AND 128),
 FOREIGN KEY (tenant_id, item_id) REFERENCES warehouse.items (tenant_id, item_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX item_compatibility_model ON warehouse.item_compatibility (tenant_id, item_id, lower(model));
ALTER TABLE warehouse.movements ADD COLUMN compat_override boolean NOT NULL DEFAULT false;
