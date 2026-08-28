#!/bin/sh
set -eu

# Bind-mounted directories are commonly created as root by Docker. Repair only
# the application data directory, then run the service without root privileges.
mkdir -p "${DATA_DIR:-/data}"
chown -R "${PUID:-1000}:${PGID:-1000}" "${DATA_DIR:-/data}"

exec su-exec "${PUID:-1000}:${PGID:-1000}" /app/dns-panel
