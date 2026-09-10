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

# Clear the source trees before extracting, because tar only ADDS.
#
# A file deleted here used to stay on the server forever, and Go compiles
# whatever is in the package directory: removing internal/work/canary.go
# locally left the server building against a version referencing struct fields
# that no longer existed. The build broke because the server had MORE code than
# the repository, which is not where anybody looks first.
#
# Only directories the repository owns entirely are cleared. data/, import/ and
# secrets/ hold the witness key, its database, the proof cache and the tokens —
# they live only on the server and are never touched.
ssh "$HOST" "cd ~/$DEST && rm -rf cmd internal proto docs deploy cuda rust/kt-akd-verify/src"

# Ship exactly the files git would, plus the stamp.
#
# This used to tar the working tree with a handful of --exclude patterns, and
# sent 237 MB over the wire every time — 620 MB of rust/kt-akd-verify/target,
# which .dockerignore then excluded from the build context anyway, plus a 28 MB
# bin/ the server has no use for. The repository itself is 2.6 MB. Every deploy
# in a session paid for a Cargo build directory that was never going to be read.
#
# `--cached --others --exclude-standard` is tracked files plus untracked ones
# that are not ignored, so a work-in-progress file still ships and anything
# .gitignore names does not. That means the rule stays right as the repository
# grows instead of being a list of exclusions somebody has to remember to
# extend — which is how the target directory got in.
#
# -T - and a NUL-delimited list, because a filename with a space would otherwise
# arrive as two truncated paths.
#
# .build-info is ignored by git and required by the Dockerfile, so it is named
# explicitly. deploy/witness.json is tracked and ships here; it is ALSO scp'd
# below, because that copy is the one the operator edits and the check after it
# is what proves the two agree.
{ git ls-files --cached --others --exclude-standard -z; printf '.build-info\0'; } \
  | tar czf - --null -T - \
  | ssh "$HOST" "cd ~/$DEST && tar xzf -"

scp -q deploy/witness.json "$HOST:~/$DEST/deploy/witness.json"

# Verify by asking the server what it now believes, never by trusting the copy.
LOCAL=$(python3 -c "import json;print(len(json.load(open('deploy/witness.json'))['logs']))")
REMOTE=$(ssh "$HOST" "cd ~/$DEST && python3 -c \"import json;print(len(json.load(open('deploy/witness.json'))['logs']))\"")
echo "config logs: local=$LOCAL remote=$REMOTE"
[ "$LOCAL" = "$REMOTE" ] || { echo "MISMATCH — the shipped config is not the one on disk here" >&2; exit 1; }
echo "shipped to $HOST:~/$DEST"
