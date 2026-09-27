#!/bin/sh
set -eu
D=/tmp/parental-control-v10

[ -f "$D/backup/.prepared" ] || { echo "No completed backup found in $D/backup; refusing to restore."; exit 1; }

[ -f "$D/web.pid" ] && kill "$(cat "$D/web.pid")" 2>/dev/null || true
[ -f "$D/daemon.pid" ] && kill "$(cat "$D/daemon.pid")" 2>/dev/null || true
sleep 1

rm -f /var/run/parental-control.sock /var/run/parental-control.nft
/usr/sbin/nft 'destroy table inet parental_control' >/dev/null 2>&1 || /usr/bin/nft 'destroy table inet parental_control' >/dev/null 2>&1 || true

rm -rf /etc/parental-control
if [ -f "$D/backup/.had-etc-parental-control" ]; then
  cp -a "$D/backup/etc-parental-control" /etc/parental-control
fi

rm -rf /var/lib/parental-control
if [ -f "$D/backup/.had-var-lib-parental-control" ]; then
  mkdir -p /var/lib
  cp -a "$D/backup/var-lib-parental-control" /var/lib/parental-control
fi

/etc/init.d/parental-control start
/etc/init.d/parental-control-web start

echo "Original OpenWrt services and parental-control data restored."
