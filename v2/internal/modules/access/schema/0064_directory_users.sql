-- Owner: access; волна 3 (C46.01, решение пользователя 2026-11-16): сотрудники входят на портал обращений учёткой AD.
-- Такой пользователь — только «заявитель» (requester), у него нет локального пароля (вход паролем запрещён: проверка
-- пароля идёт через каталог). Локальные пользователи — как раньше.
ALTER TABLE access.users DROP CONSTRAINT users_role_check;
ALTER TABLE access.users ADD CONSTRAINT users_role_check CHECK (role IN ('admin','operator','viewer','requester'));
ALTER TABLE access.users ADD COLUMN auth_source text NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local','directory'));
ALTER TABLE access.users ADD CONSTRAINT users_directory_requester CHECK (auth_source = 'local' OR role = 'requester');
