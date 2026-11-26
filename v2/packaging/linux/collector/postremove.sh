#!/bin/sh
# C52.04: после удаления surveyscan-collector. deb purge — удаляются регистрация, ключи, очередь и пользователь службы;
# deb remove и rpm -e — данные остаются (/etc/surveyscan-collector, /var/lib/surveyscan-collector), повторная установка их подхватит.
set -e
NAME=surveyscan-collector
if [ -d /run/systemd/system ]; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
if [ "${1:-}" = purge ]; then
  rm -rf /etc/$NAME /var/lib/$NAME
  if getent passwd $NAME >/dev/null 2>&1; then userdel $NAME >/dev/null 2>&1 || true; fi
  if getent group $NAME >/dev/null 2>&1; then groupdel $NAME >/dev/null 2>&1 || true; fi
fi
exit 0
