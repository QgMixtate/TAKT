# C13 — ручное проверяемое обновление

Реализованы prepare/apply/recover/status, signed releases, persistent fence/journal и точная
проверка схемы. Process-controller rehearsal:19 checks passed с настоящими server/PG/TLS,
failed startup/rollback, SIGKILL и изолированной compiled schema34 fixture. Два независимых
Debian12/systemd VM прошли actual reboot и combined server/collector/agent update (9+9 checks).
Production KMS/HA/physical power loss остаются вне этой bounded E1 проверки.

Каждый новый bundle содержит `schema.json` из `surveyscan-server schema-catalog`:
ordered migration ID/owner/SHA256 точных embedded SQL bytes, без DB/SQL contents.
`schema-check` с private PG credentials требует точного совпадения DB ledger с бинарником.
Каталоги проверяются после подписи и сверяются с исполняемым schema-catalog до остановки сервиса.
Wire major и existing SQL prefix должны совпасть. Unit/sysusers changes требуют отдельной
установки и приёмки, не применяются переключением symlink. Первичная установка должна
иметь новые ConditionPathExists=!/opt/surveyscan/update.fence во всех server/migrate/collector/agent units.

```sh
python3 scripts/updater.py prepare --root / --bundle /private/verified-release \
  --public-key /trusted/release.pub
python3 scripts/updater.py status --root / --public-key /trusted/release.pub
python3 scripts/updater.py apply --root / --public-key /trusted/release.pub \
  --health-url https://server.example/health/ready --ca-file /trusted/https-ca.pem
```

Команды apply/recover CLI обслуживают выбранный combined server на systemd;
`--components server collector agent` добавляет совместно установленные службы. Server обязателен;
набор сохраняется в journal и должен совпадать при recover. Prepare/status
также работают на staging root. Operator root владеет program dirs; service users их не меняют.
Корневой URL readiness проверяется с TLS, redirects запрещены. HTTP допустим лишь по явному
флагу --dev-loopback-http и literal loopback. Нет паролей/token в argv/EnvironmentFile.
Transient schema-check/migrate tasks имеют User/Group surveyscan-server, LoadCredential PG
password, private UMask и sandbox properties. Transient D-Bus команды используют явный
`/run/credentials/<unique-unit>.service/pg_password`: expansion `%d` здесь не применяется.
Actual transient tasks и healthy-проверка каждой выбранной службы выполнены в двух VM.

Prepare проверяет новую подпись/bytes/modes, immutable version directory и каталог, публикует
кандидат, оставляя current и процессы на старой версии. Повтор точно той же signed версии
после rollback допускается; тихая подмена существующей версии и implicit downgrade запрещены.
Schema-changing update дополнительно требует `--checkpoint /private/common-checkpoint`,
проверенный через checkpoint.py; digest повторно сверяется перед apply. Полнота/согласованность
backup и отдельная recovery custody остаются operator prerequisite.

Apply удерживает общий flock, сохраняет fsync journal/fence, останавливает выбранные службы/migrate,
проверяет actual old DB schema, запускает candidate migrate, повторно проверяет новую схему,
атомарно переключает current, снимает gate и ждёт active+ready. Configs/keys/state не заменяются.
При failed startup сначала снова ставится gate и останавливается новый process. Возврат разрешён
только если actual DB точно подходит старому binary. Schema downgrade никогда не выполняется.
Если старая схема не совпадает или restart не удался, gate остаётся и journal= recovery_required.

```sh
python3 scripts/updater.py recover --root / --public-key /trusted/release.pub \
  --health-url https://server.example/health/ready --ca-file /trusted/https-ca.pem
```

Recover заново проверяет installed signatures и actual DB. Interrupted migrating/start выбирает
подходящую новую версию либо совместимую старую; unknown/drifted schema не запускает writers.
Не удалять gate/редактировать current вручную ради запуска несовместимого binary. Если ни один
каталог не подходит, использовать изолированное восстановление общего checkpoint по BACKUP.md.
Rolled_back и recovery_required возвращают ненулевой exitcode, даже если прежний сервис доступен.

`scripts/update_smoke.py` проверяет настоящие signed binaries/PG/TLS/version/login/UID,
неизменность private configs/TLS keys/artifact, запрет downgrade, bad-listen startup rollback,
actual SIGKILL после committed migrate0, durable fence/journal и recovery. Drift — явная test SQL
metadata fixture. Отдельный compiled candidate с test-only appended migration34 реально меняет
схему изолированной БД: проверяются обязательный checkpoint, committed DDL, отказ старого33
rollback и явное восстановление новой версии. В продуктовых SQL migration34 нет.
Real systemd controller и две свежие Debian12 VM проверены; physical power loss ещё unrun. Проверка C11→current
реальных миграций отдельно в upgrade_smoke.py. Legacy unsigned staging не считается установкой.

## Заметки к выпускам (что проверить после обновления)
- **0047 (логин AD у людей из каталога):** поле «Логин AD» заполняется при **полной** синхронизации каталога
  (раз в `full_sync_hours` или кнопкой в «Оргструктуре»); до неё у существующих людей оно пустое — это не ошибка.
- **0052–0056 (схема сети, WinRM без PEM, CA домена, Kerberos, вывод актива из учёта):** после обновления центра
  обязательно пересобрать и выложить Web (раздел «Обновление» в OPERATIONS.md), иначе новых разделов и кнопок нет.
- **Сверка отпечатка ключа SSH** при запоминании «при первом подключении»: collector запоминает тот ключ, который
  предложил узел (часто ECDSA, не ed25519). Сверять со всеми ключами узла:
  `for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$f"; done` — один из отпечатков совпадёт.

- **0058 (присутствие узлов, C21):** узел подсети становится «пропал» только после **3 полных обследований подряд**
  без него (было — после одного); обследование с ошибками пропуском не считается. Узлы, уже отмеченные «пропал»
  до обновления, остаются такими до следующего обнаружения. В Web у узла видно «не найден N из 3», под таблицей —
  журнал «Изменения присутствия» (появился / пропал / вернулся). Нужна пересборка Web.
- **Шифрование portable-пакетов (C23):** «Источники данных» → «Portable-аудит» → «Включить шифрование» (нужно
  хранилище секретов центра: OpenBao `integrations_path` или каталог `integrations` без OpenBao). После включения
  команда `init` в Web содержит `--center-key`; на уже подготовленных ПК — `surveyscan-portable center-key --state …
  --center-key …`. Зашифрованный пакет загружается только через Web/HTTPS (консольный `portable-import` его не
  принимает). Ключ входит в резервную копию хранилища секретов: без него зашифрованные пакеты не прочитать.
- **0059–0060 (склад, волна 2):** новый раздел Web «Склад»; после обновления центра пересобрать Web. Справочники
  (склады, каталог) пустые — заводит администратор (OPERATIONS.md, раздел 13). Новые права: просмотр склада — все,
  операции — оператор/администратор, списание и закрытие инвентаризации — администратор.
- **0062–0064 (ключ SSH из центра, обращения, портал):** у SSH-учётки можно выбрать «ключ, созданный центром» —
  открытый ключ скопировать в `authorized_keys`. Новый раздел «Обращения» (инциденты, проблемы). Вход сотрудников
  на портал учёткой AD — только при настроенной синхронизации каталога (OPERATIONS.md, раздел 14). Пересобрать Web.
- **0065 (каталог услуг и заявки, C48):** новые таблицы itsm.catalog_items и itsm.approvals, у обращений — услуга и
  значения формы. Каталог после обновления пуст: администратор заводит услуги в «Обращения → Каталог услуг».
- **0066 (изменения, C49):** таблица itsm.change_windows (окно, риск, планы). Изменения согласует администратор;
  вкладка «Календарь изменений» в разделе «Обращения». Пересобрать Web.
- **0067 (SLA, C50):** таблицы itsm.business_hours, itsm.sla_policies, itsm.sla_timers. Таймеры заводятся для
  обращений, созданных после обновления. Проверить в «Обращения → SLA» часовой пояс и рабочие часы организации.
- **0068 (коды регистрации, C52.01):** таблицы sources.registration_codes и sources.registration_uses. Новый раздел
  «Источники данных → Установка»; команды `register` у агента и collector. Прежняя установка (grant) работает как раньше.
- **0069 (узлы portable-аудита, C23.04):** таблица sources.portable_discovery_hosts — найденные обследованием узлы
  из portable-пакетов (исход, причина, имя профиля); данные не переносятся, старые пакеты импортируются как раньше.
  Приватная фикстура update_smoke сдвинута на 0070.
- **0070 (РСМ, C54.01):** таблицы cmdb.directions, environments, components, binding_rules, bindings,
  component_dependencies; у cmdb.services новые необязательные поля (направление, владелец, ответственный ИТ, окно
  обслуживания). Сервисы C26 становятся системами с теми же идентификаторами; данные не переносятся.
  Приватная фикстура update_smoke сдвинута на 0071.
- **0071 (состояние РСМ, C54.03):** таблицы cmdb.host_states и cmdb.node_states — производные агрегаты светофора,
  пересчитываются фоновой задачей раз в 5 минут (роль worker / all); данные не переносятся. Приватная фикстура
  update_smoke сдвинута на 0072.
- **0075 (снимки платформ, C57.01):** новые таблицы cmdb.platform_instances, platform_snapshots, platform_objects,
  platform_relations — экземпляры платформ (KVM, vSphere, oVirt/zVirt, Redfish, AD…), их объекты и связи; данные
  приходят от collector, существующие таблицы не меняются. Приватная фикстура update_smoke сдвинута на 0076.
- **0074 (плотный реестр хостов, C53.04):** новая производная таблица cmdb.host_registry (имя, IP, ОС, площадка,
  ответственный, система, свежесть). После обновления заполняется фоновой задачей при старте центра и затем раз в
  5 минут; до первого заполнения раздел «Хосты» пуст. Удалять и восстанавливать её из копии не нужно — строится
  заново. Приватная фикстура update_smoke сдвинута на 0075.
- **0073 (карточки, C53.03):** cmdb.components.role, cmdb.services.on_call и backup_subject_id — необязательные поля
  карточек системы и компонента. Приватная фикстура update_smoke сдвинута на 0074.
- **0072 (экран «Системы», C53.02):** у cmdb.node_states новые поля fresh и problems (производные; заполняются
  следующим пересчётом раз в 5 минут). Приватная фикстура update_smoke сдвинута на 0073.
- **Замечания стенда №19 (№54–59):** включение ранее отключённой цели сбора теперь заново регистрирует её (прежний
  источник остаётся в истории); Rust-агент Windows после `install-service` сразу запускает службу; в карточке актива —
  блок «История изменений» (C09, необязательное поле `history`).
- **Сессии браузера (17.11):** после обновления страница не выкидывает на вход (сессия восстанавливается по cookie).
  Сессии, открытые до обновления центра, восстановиться не смогут — один повторный вход.
