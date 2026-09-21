#!/bin/sh
# Run a one-shot witness command that needs the database, with the witness down.
#
#   usage: deploy/oneshot.sh [ssh-host] -- <args...>
#          deploy/oneshot.sh -- -repair-cosigner-name
#          deploy/oneshot.sh -- -retract-fork example.com/log -reason "..."
#
# bbolt takes an exclusive lock on witness.db with a five-second timeout, so
# anything that opens the store cannot run beside a live witness. That makes
# every one-shot correction — -repair-cosigner-name, -retract-fork, -genkey —
# a stop/run/start, and stop/run/start typed by hand is how a witness ends up
# left down: the run fails, the person reads the error, and the `up` never
# happens. The trap is the whole point of this file.
#
# The config path is /config/witness.json, not the image's default of
# /data/witness.json. The compose file mounts the operator's copy there and
# overrides CMD accordingly; a one-shot that does not override it in the same
# way exits on a missing file, which is how this script came to exist.
set -eu

HOST="${1:-docker-services-ts}"
[ "$HOST" = "--" ] || shift
[ "${1:-}" = "--" ] && shift
[ $# -gt 0 ] || { echo "usage: $0 [ssh-host] -- <witness args...>" >&2; exit 2; }

# Quote each argument for the remote shell, so a -reason with spaces survives.
REMOTE_ARGS=""
for a in "$@"; do
  REMOTE_ARGS="$REMOTE_ARGS '$(printf '%s' "$a" | sed "s/'/'\\\\''/g")'"
done

# Detached, because an ssh that dies mid-sequence must not take the sequence
# with it and leave the witness stopped. This is not hypothetical: a laptop
# dropping off the tailnet between `stop` and `up` is exactly what happened.
ssh -n "$HOST" "cat > ~/kt-witness/.oneshot.sh <<'REMOTE'
#!/bin/bash
cd ~/kt-witness
trap 'docker compose up -d kt-witness' EXIT
set -x
docker compose stop kt-witness
docker compose run --rm kt-witness -config /config/witness.json $REMOTE_ARGS
REMOTE
chmod +x ~/kt-witness/.oneshot.sh
nohup ~/kt-witness/.oneshot.sh > ~/kt-witness/.oneshot.log 2>&1 &
echo started"

echo "==> running, witness is down until it finishes"
until ssh -n "$HOST" "grep -q 'up -d' ~/kt-witness/.oneshot.log" 2>/dev/null; do sleep 2; done
ssh -n "$HOST" "cat ~/kt-witness/.oneshot.log; rm -f ~/kt-witness/.oneshot.sh ~/kt-witness/.oneshot.log"

"$(dirname "$0")"/assert-running.sh "$HOST"
