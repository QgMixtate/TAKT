#!/bin/sh
# C52.04: проверка пакетов deb/rpm внутри контейнера дистрибутива (без systemd): установка, пользователь и каталоги,
# бинарник запускается, обновление сохраняет регистрацию, удаление и (deb) purge. Запускает scripts/package_smoke.py.
#   package_install_check.sh deb|rpm КАТАЛОГ_v1 КАТАЛОГ_v2
set -eu
FORMAT=$1 V1=$2 V2=$3
fail() { echo "FAIL: $*" >&2; exit 1; }
mode() { stat -c %a "$1"; }
owner() { stat -c %U "$1"; }

install_pkg() { if [ "$FORMAT" = deb ]; then dpkg -i "$@" >/dev/null; else rpm -i "$@"; fi; }
upgrade_pkg() { if [ "$FORMAT" = deb ]; then dpkg -i "$@" >/dev/null; else rpm -U "$@"; fi; }
remove_pkg() { if [ "$FORMAT" = deb ]; then dpkg -r "$1" >/dev/null; else rpm -e "$1"; fi; }
pkg_version() { if [ "$FORMAT" = deb ]; then dpkg-query -W -f '${Version}' "$1"; else rpm -q --qf '%{VERSION}' "$1"; fi; }
pkgs() { ls "$1"/surveyscan-"$2"*."$FORMAT"; }

for kind in agent collector; do
  n=surveyscan-$kind
  [ $kind = agent ] && cfg=config.json || cfg=collector.json
  install_pkg "$(pkgs "$V1" $kind)"
  getent passwd $n >/dev/null || fail "$n: нет пользователя службы"
  [ "$(mode /etc/$n)" = 700 ] && [ "$(mode /var/lib/$n)" = 700 ] || fail "$n: права каталогов"
  [ -f /usr/lib/systemd/system/$n.service ] && [ -f /usr/lib/systemd/system/$n-register.service ] || fail "$n: нет unit-файлов"
  [ -x /usr/sbin/$n-setup ] && [ -f /usr/share/$n/register.env.example ] || fail "$n: нет setup/примера"
  /usr/bin/$n version >/dev/null 2>&1 || /usr/bin/$n --version >/dev/null 2>&1 || fail "$n: бинарник не запускается"
  # setup: без root — отказ; без параметров — подсказка (код возврата 2)
  if su -s /bin/sh -c "/usr/sbin/$n-setup --env /dev/null" $n 2>/dev/null; then fail "$n: setup без root"; fi
  rc=0; /usr/sbin/$n-setup </dev/null >/dev/null 2>&1 || rc=$?; [ $rc = 2 ] || fail "$n: setup без параметров: $rc"
  # неизвестный параметр в register.env — отказ без выполнения (файл не исполняется как shell)
  printf 'REG_CODE=x\nTOUCH=$(touch /tmp/pwned)\n' > /tmp/bad.env
  if /usr/sbin/$n-setup --env /tmp/bad.env >/dev/null 2>&1; then fail "$n: принят неизвестный параметр"; fi
  [ ! -e /tmp/pwned ] || fail "$n: register.env выполнен как shell"
  # №128: код не того вида — отказ с пояснением до обращения к сети
  [ $kind = agent ] && flag=--collector || flag=--center
  if out=$(echo 'not-a-code' | /usr/sbin/$n-setup $flag https://127.0.0.1:9 --fingerprint ab 2>&1); then fail "$n: принят код не того вида"; fi
  echo "$out" | grep -q 'не похож на код' || fail "$n: нет пояснения про вид кода: $out"
  # «регистрация» (как после setup) — обновление пакета её сохраняет
  echo '{"registered":true}' > /etc/$n/$cfg; chmod 600 /etc/$n/$cfg
  echo state > /var/lib/$n/marker
  v1=$(pkg_version $n)
  upgrade_pkg "$(pkgs "$V2" $kind)"
  [ "$(pkg_version $n)" != "$v1" ] || fail "$n: версия не сменилась при обновлении"
  grep -q registered /etc/$n/$cfg && [ -f /var/lib/$n/marker ] || fail "$n: обновление потеряло регистрацию"
  out=$(/usr/sbin/$n-setup --env /dev/null 2>&1) || fail "$n: setup на зарегистрированном: $out"
  echo "$out" | grep -q 'уже зарегистрирован' || fail "$n: setup не увидел регистрацию"
  remove_pkg $n
  [ ! -e /usr/bin/$n ] && [ ! -e /usr/lib/systemd/system/$n.service ] || fail "$n: файлы программы остались после удаления"
  grep -q registered /etc/$n/$cfg || fail "$n: удаление без purge стёрло регистрацию"
  if [ "$FORMAT" = deb ]; then
    dpkg -P $n >/dev/null
    [ ! -e /etc/$n ] && [ ! -e /var/lib/$n ] || fail "$n: purge оставил данные"
    if getent passwd $n >/dev/null; then fail "$n: purge оставил пользователя"; fi
  else
    # rpm: повторная установка подхватывает прежнюю регистрацию
    install_pkg "$(pkgs "$V2" $kind)"
    grep -q registered /etc/$n/$cfg || fail "$n: повторная установка не нашла регистрацию"
    remove_pkg $n
  fi
  echo "ok $n"
done
echo PASS
