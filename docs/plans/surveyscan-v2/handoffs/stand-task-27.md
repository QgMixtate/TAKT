# Задание №27 для локального Claude (стенд awm.local): установщики C52.04 — скачивание из Web, MSI, deb, portable, Astra

**Этап:** C52.04 (AC C52-08). **«Да» пользователя (26.11, «делай рекомендуемо»):** выкладка выпуска с файлами установки
на центр стенда; агент через MSI на win-ar; collector через deb на Linux-ВМ стенда; portable с флешки на ПК пользователя;
агент через deb на Astra — **только если на стенде есть ВМ с Astra** (иначе пункт пропустить и написать «нет ВМ»).

**Правила — как всегда.** Ничего вне 10.170.108.0/24; DC — только чтение. Коды регистрации, пароли, токены, закрытые
ключи — не в чат, отчёт и файлы (код вводится через stdin или параметр MSI; в отчёт — «код создан / использован»).
Отпечаток центра и SHA-256 файлов — можно. Подтверждения в Web не подменять. Действия вне задания — только с «да»
пользователя. Что делает каждый пункт и как проверить — ниже; руководство — `v2/deploy/OPERATIONS.md`, раздел 16.

## 1. Выпуск с файлами установки и центр
Последний `develop` с зелёным CI (не раньше коммита с этим заданием). Миграций — 76 (новых нет).
1. Инструменты (один раз): `go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.41.1`; `sudo apt-get install -y wixl
   msitools musl-tools gcc-mingw-w64-x86-64`; `rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu`.
2. Сборка: `cd v2 && make build rust packages VERSION=0.0.0-c27` и Web (`cd web && npm ci && npm run generate && npm run
   build`). В `.dist/packages` — 12 файлов + SHA256SUMS (агент и collector: msi, zip, deb, rpm, tar.gz; portable: Linux, .exe).
3. Ключ выпуска стенда (только для стенда, не боевой): `openssl genpkey -algorithm ED25519 -out ~/.config/surveyscan-release/stand.key`
   (каталог 0700, ключ 0600), открытый — `openssl pkey -in … -pubout -out ~/.config/surveyscan-release/stand.pub`.
4. Выпуск: `python3 scripts/release.py build --version 0.0.0-c27 --output ~/surveyscan-release/0.0.0-c27 --installers .dist/packages`,
   `release.py sign --bundle … --key …stand.key`, `release.py stage --bundle … --public-key …stand.pub --root ~/surveyscan-release/stage-c27`.
5. Центр: перезапуск как обычно, один раз с `--release-dir ~/surveyscan-release/stage-c27/opt/surveyscan/releases/0.0.0-c27
   --release-public-key ~/.config/surveyscan-release/stand.pub` (запоминаются в `vm.json`, ночная копия их сохранит).
   В журнале центра: «файлы установки: выпуск 0.0.0-c27, 12 файлов, подпись проверена центром: true».
6. Web, администратор: «Источники данных» → «Установка» → **«Скачать»** — «выпуск 0.0.0-c27 · подпись выпуска проверена
   центром», Windows/Linux, по 6 файлов. Оператор (если есть учётка) видит «Скачать», но не коды. Скриншот.
   Скачать любой файл из браузера и сравнить `sha256sum` с колонкой SHA-256 и `.dist/packages/SHA256SUMS`.
   Аудит: в БД `audit.audit_events` есть `installer.downloaded` с именем файла.

## 2. Collector через deb (Linux-ВМ стенда без collector)
ВМ — предложи пользователю (calc-dep или другая Linux-ВМ, **не** центр: там работает collector стенда). Порт — свободный,
например 8444.
1. Web: код «collector площадки» на 1 установку. Скачать `surveyscan-collector_0.0.0~c27-1_amd64.deb` из Web на ВМ.
2. `sudo apt install ./surveyscan-collector_*.deb` → служба **не** запущена (`systemctl is-active` — inactive).
3. `echo <код> | sudo surveyscan-collector-setup --center https://10.170.108.2:<порт центра> --fingerprint <отпечаток> --listen 0.0.0.0:8444`
   → «служба … запущена»; Web: новый источник collector активен; `systemctl status` — active, пользователь `surveyscan-collector`.
4. Повторная установка пакета (`sudo apt install --reinstall ./…deb`) — служба перезапущена, источник тот же (регистрация сохранена).
5. Неверный отпечаток на втором коде — отказ до отправки кода (код остаётся неиспользованным в Web).
6. После проверок — спросить пользователя: оставить второй collector или `sudo apt purge surveyscan-collector` (по умолчанию —
   purge: на площадке остаётся один collector стенда).

## 3. Агент через MSI на win-ar
Через collector стенда (`https://10.170.108.2:18443` или тот, что указан в Web у collector площадки).
1. Web: код «агент на ПК/сервер», ОС Windows, collector стенда, 1 установка. Скачать `surveyscan-agent_0.0.0-c27_windows_x64.msi`
   (на win-ar — браузером из Web или копией; SHA-256 сверить с Web).
2. Сначала отказ: `msiexec /i … /qn /l*v C:\Temp\msi-bad.log COLLECTOR_URL=https://10.170.108.2:18443 CENTER_FINGERPRINT=<64 × «ab»>
   REG_CODE=<код>` → код 1603, службы `SurveyscanAgent` нет, `C:\Program Files\SurveyScan\Agent` нет; в журнале
   `findstr` по коду — пусто. Код в Web остаётся «0 из 1».
3. Установка: тот же MSI с верным отпечатком (`/l*v C:\Temp\msi.log`) → код 0; служба `SurveyscanAgent` — Running, LocalSystem,
   Automatic; в Web — источник агента активен, heartbeat свежий; через ≤ 15 мин — инвентарь.
4. **Без дублей (C52-08):** карточка хоста win-ar — тот же актив, что был по WinRM (asset_uid не сменился), среди
   источников — агент; в «Хостах» нет второго win-ar. Скриншот карточки и списка источников.
5. Агент остаётся установленным (нужен для агентской части приёмки E2). Удаление — по решению пользователя
   (`msiexec /x … /qn`; регистрация в `%ProgramData%\SurveyScan\agent` сохраняется, `REMOVE_DATA=1` — удаляет).

## 4. Portable с флешки (ПК пользователя, Windows)
1. Скачать из Web `surveyscan-portable_0.0.0-c27_windows_x64.exe` на флешку; SHA-256 — как в Web. SmartScreen при запуске
   может предупредить (файл без Authenticode, решение C52.05) — отметить в отчёте, как выглядело.
2. Как в задании №19, часть A: `init` (блок — в Web «Portable-аудит»), `collect` этого ПК, пакет — загрузить в Web.
   Следов вне каталога на флешке нет (проверить `%LOCALAPPDATA%`, `%ProgramData%` — нового каталога SurveyScan нет).
3. Повторная загрузка того же пакета — без изменений; ПК — один актив (не второй). Мастер (`wizard`) — пока прежнего вида:
   новый мастер по утверждённым макетам — отдельной частью C52.04.

## 5. Astra (если есть ВМ)
1. `cat /etc/astra_version`, режим ЗПС (`astra-digsig-control status` или аналог). В режиме ЗПС (проверка подписи ELF)
   агент не запустится без ключа заказчика — **это ожидаемо** (C52.05): записать, что показала система, и не отключать ЗПС.
2. Вне ЗПС: Web → код агента (Linux), скачать `surveyscan-agent_0.0.0~c27-1_amd64.deb`, `sudo apt install ./…deb`,
   `echo <код> | sudo surveyscan-agent-setup --collector https://10.170.108.2:18443 --fingerprint <отпечаток>` → служба active,
   в Web — источник и инвентарь (ОС — Astra).

## Отчёт
По разделам 1–5: sha коммита, строка журнала центра про файлы установки, скриншоты («Скачать», карточка win-ar, источники),
SHA-256 скачанных файлов = Web, коды возврата msiexec (1603 / 0), состояние служб, asset_uid win-ar до и после,
что с Astra. Новые замечания — с №118.
