-- Owner: sources; стенд №13 (решение пользователя 2026-11-16): ключ SSH-учётки можно сгенерировать в центре — закрытый
-- ключ сразу уходит в хранилище секретов и не покидает центр, а открытый (строка для authorized_keys) хранится здесь и
-- показывается в Web. При смене секрета на пароль или свой ключ открытый ключ очищается.
ALTER TABLE sources.collect_credentials ADD COLUMN public_key text CHECK (length(public_key) BETWEEN 1 AND 1024);
