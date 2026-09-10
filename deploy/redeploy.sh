#!/bin/sh
# Ship, build, restart, and say what happened — the whole inner loop, once.
#
#   usage: deploy/redeploy.sh [witness|workers|all]   (default: all)
#
# This exists because the loop was five commands typed in order across two
# hosts, and the two that got skipped under time pressure were always the same
# two: the test run, and checking that the thing actually came back up. A
# deploy that is one command is a deploy where neither is optional.
#
# It refuses on a failing test rather than shipping and telling you afterwards.
set -eu

WHAT="${1:-all}"
HOST="${KT_WITNESS_HOST:-docker-services-ts}"
GPU="${KT_GPU_HOST:-docker-gpu-ts}"
here=$(dirname "$0")/..

echo "==> tests"
( cd "$here" && go build ./... && go test ./... >/dev/null ) \
  || { echo "tests failed; nothing shipped" >&2; exit 1; }

if [ "$WHAT" = all ] || [ "$WHAT" = witness ]; then
  echo "==> witness: ship"
  "$here/deploy/ship.sh" "$HOST" >/dev/null
  echo "==> witness: build and restart"
  ssh "$HOST" "cd ~/kt-witness && docker compose build kt-witness >/dev/null && docker compose up -d kt-witness" >/dev/null
fi

if [ "$WHAT" = all ] || [ "$WHAT" = workers ]; then
  # The GPU box takes a cross-compiled binary rather than an image: it runs one
  # Go program with no Rust in it, so a container round trip buys nothing.
  echo "==> gpu-box: build, copy, restart"
  ( cd "$here" && GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
      -o /tmp/kt-worker-linux ./cmd/kt-worker )
  scp -q /tmp/kt-worker-linux "$GPU:~/kt-worker/kt-worker.new"
  # `exit 0` because the backgrounded worker keeps the ssh session's stdout
  # open otherwise and this hangs until the lease expires.
  ssh "$GPU" 'cd ~/kt-worker && pkill -f "^\./kt-worker " 2>/dev/null; sleep 3; \
    mv kt-worker.new kt-worker && chmod +x kt-worker && \
    set -a && . ./work.env && set +a && \
    setsid nohup ./kt-worker -server "$KT_WORK_SERVER" -akd-origins "$KT_WORK_ORIGINS" \
      -name gpu-box > worker.log 2>&1 < /dev/null & disown; exit 0' >/dev/null 2>&1 || true
fi

echo "==> settling"
sleep 12

echo "==> what came back:"
ssh "$HOST" 'cd ~/kt-witness && docker compose logs --since=30s kt-witness 2>&1 \
  | grep -E "worker connected|scratch space|level=ERROR" | tail -6' || true
echo "done. Logs: deploy/loki-tunnel.sh, then query Loki on 127.0.0.1:3100"
