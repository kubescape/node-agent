#!/bin/sh
# Run sign-object as the owner of the bind-mounted /work, so files it writes
# (keys, signed profiles) are owned by the invoking user — no `--user` flag
# needed. Falls back to running directly if /work isn't a bind mount or is
# already root-owned.
set -e
if [ -d /work ]; then
  uid="$(stat -c %u /work 2>/dev/null || echo 0)"
  gid="$(stat -c %g /work 2>/dev/null || echo 0)"
  if [ "$uid" != "0" ]; then
    exec su-exec "${uid}:${gid}" sign-object "$@"
  fi
fi
exec sign-object "$@"
