#!/bin/sh
# Squid drops to the proxy user, which cannot open /dev/stdout.
# The access log stays on a file the proxy user owns, and this script
# copies new lines to the container stdout for `docker compose logs`.
set -eu
mkdir -p /var/spool/squid /var/log/squid
touch /var/log/squid/access.log /var/log/squid/cache.log
chown -R proxy:proxy /var/spool/squid /var/log/squid
squid -z -f /etc/squid/squid.conf || true
squid -N -f /etc/squid/squid.conf &
pid=$!
tail -n 0 -F /var/log/squid/access.log &
tailpid=$!
trap 'kill "$pid" "$tailpid" 2>/dev/null || true' TERM INT
wait "$pid"
status=$?
kill "$tailpid" 2>/dev/null || true
exit "$status"
