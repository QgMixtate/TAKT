#!/bin/sh
# C52.04: перед удалением surveyscan-agent (deb: remove/purge; rpm: 0 — удаление). При обновлении ничего не делает.
set -e
NAME=surveyscan-agent
case "${1:-}" in remove|purge|0) ;; *) exit 0 ;; esac
if [ -d /run/systemd/system ]; then
  systemctl disable --now $NAME.service $NAME-register.service >/dev/null 2>&1 || true
fi
exit 0
