#!/bin/sh
set -eu
D=/tmp/parental-control-v10
rm -rf "$D/backup"
mkdir -p "$D/backup"

cp -p /usr/sbin/parental-control "$D/backup/parental-control.original"
cp -p /usr/sbin/parental-control-web "$D/backup/parental-control-web.original"

if [ -d /etc/parental-control ]; then
  touch "$D/backup/.had-etc-parental-control"
  cp -a /etc/parental-control "$D/backup/etc-parental-control"
fi

if [ -d /var/lib/parental-control ]; then
  touch "$D/backup/.had-var-lib-parental-control"
  cp -a /var/lib/parental-control "$D/backup/var-lib-parental-control"
fi

touch "$D/backup/.prepared"

printf '%s\n' "Backup created in $D/backup"
printf '%s\n' "Copy your reconstructed test binaries into $D as parental-control and parental-control-web."
printf '%s\n' "The restore script will restore both /etc/parental-control and /var/lib/parental-control."
