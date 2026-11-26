#!/bin/sh
# C52.04: после установки/обновления пакета surveyscan-collector (deb: configure; rpm: 1 — установка, 2 — обновление).
# Регистрация не выполняется здесь: служба стартует только при наличии collector.json (обновление сохраняет регистрацию)
# или регистрируется по register.env.
set -e
NAME=surveyscan-collector
case "${1:-}" in configure|1|2|"") ;; *) exit 0 ;; esac
if ! getent group $NAME >/dev/null 2>&1; then groupadd --system $NAME; fi
if ! getent passwd $NAME >/dev/null 2>&1; then
  shell=/usr/sbin/nologin; [ -x $shell ] || shell=/sbin/nologin
  useradd --system --gid $NAME --home-dir /var/lib/$NAME --no-create-home --shell $shell --comment "SurveyScan" $NAME
fi
install -d -m 0700 /etc/$NAME /var/lib/$NAME
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable $NAME.service $NAME-register.service >/dev/null 2>&1 || true
  if [ -f /etc/$NAME/collector.json ]; then
    systemctl restart $NAME.service || echo "$NAME: служба не запустилась — journalctl -u $NAME" >&2
  elif [ -f /etc/$NAME/register.env ]; then
    systemctl start --no-block $NAME-register.service || true
  else
    echo "$NAME установлен. Регистрация: sudo $NAME-setup --center https://ЦЕНТР --fingerprint ОТПЕЧАТОК"
  fi
fi
exit 0
