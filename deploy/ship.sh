#!/bin/sh
# Ship the source to the witness host and stamp the build.
#
# This exists because the documented sequence has three steps that have each
# gone wrong at least once: an exclude pattern that silently swallowed
# deploy/witness.json, a config that was present but stale, and a running binary
# nobody could identify. Doing them by hand means doing them right every time.
#
#   usage: deploy/ship.sh [ssh-host]     (default: docker-services-ts)
#
# It does NOT build or restart anything. Deciding when to interrupt a running
# witness is a judgement call and stays with the operator.
set -eu

HOST="${1:-docker-services-ts}"
DEST="${DEST:-kt-witness}"

# Stamp first, so the tar carries it. A dirty tree is recorded as such: a commit
# hash that does not describe the bytes being shipped is worse than no hash.
DIRTY=""
git diff --quiet HEAD 2>/dev/null || DIRTY="-dirty"
cat > .build-info <<INFO
commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)${DIRTY}
date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
INFO
echo "stamping: $(sed -n 's/^commit=//p' .build-info)"

# --exclude patterns are matched against every path component by bsdtar, so any
# pattern containing witness.json would also match deploy/witness.json. Do not
# add one; the config is copied explicitly below.
tar czf - --exclude='.git' --exclude='data' --exclude='*.key' . \
  | ssh "$HOST" "cd ~/$DEST && tar xzf -"

scp -q deploy/witness.json "$HOST:~/$DEST/deploy/witness.json"

# Verify by asking the server what it now believes, never by trusting the copy.
LOCAL=$(python3 -c "import json;print(len(json.load(open('deploy/witness.json'))['logs']))")
REMOTE=$(ssh "$HOST" "cd ~/$DEST && python3 -c \"import json;print(len(json.load(open('deploy/witness.json'))['logs']))\"")
echo "config logs: local=$LOCAL remote=$REMOTE"
[ "$LOCAL" = "$REMOTE" ] || { echo "MISMATCH — the shipped config is not the one on disk here" >&2; exit 1; }
echo "shipped to $HOST:~/$DEST"
