#!/bin/sh
# Initialise the drive on first start, optionally create the first admin,
# then run the requested tether command against it.
set -eu
DRIVE="${TETHER_ROOT:-/data/drive}"
mkdir -p "$DRIVE"
if [ ! -d "$DRIVE/.tether" ]; then
  tether init "$DRIVE" >/dev/null 2>&1 || true   # another service may have won the race
  [ -d "$DRIVE/.tether" ] || { echo "tether: could not initialise $DRIVE" >&2; exit 1; }
fi
if [ "${1:-}" = "serve" ] && [ -n "${TETHER_ADMIN_USER:-}" ]; then
  if ! tether --root "$DRIVE" user list | grep -q "^${TETHER_ADMIN_USER} "; then
    [ -n "${TETHER_ADMIN_PASSWORD:-}" ] || { echo "tether: set TETHER_ADMIN_PASSWORD" >&2; exit 1; }
    printf '%s\n' "$TETHER_ADMIN_PASSWORD" | tether --root "$DRIVE" --actor system:bootstrap \
      user add "$TETHER_ADMIN_USER" --role admin --password-stdin
  fi
fi
exec tether --root "$DRIVE" "$@"
