#!/bin/sh
# Ship, build, restart, and say what happened — the whole inner loop, once.
#
#   usage: deploy/redeploy.sh [witness|mac|gpu|workers|all]   (default: all)
#
#   witness  the server: ship, rebuild the image, recreate the container
#   mac      this laptop's worker, rebuilt and restarted in place
#   gpu      the GPU box's worker, cross-compiled and copied
#   workers  mac and gpu
#   all      everything
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
# Where this laptop's worker dials. From secrets/work.env where it is set;
# otherwise the LAN address the witness publishes the work channel on.
MAC_SERVER="${KT_WORK_SERVER:-192.168.0.146:18090}"

echo "==> tests"
( cd "$here" && go build ./... && go test ./... >/dev/null ) \
  || { echo "tests failed; nothing shipped" >&2; exit 1; }

if [ "$WHAT" = all ] || [ "$WHAT" = witness ]; then
  echo "==> witness: ship"
  "$here/deploy/ship.sh" "$HOST" >/dev/null
  echo "==> witness: build and restart"
  ssh -n "$HOST" "cd ~/kt-witness && docker compose build kt-witness >/dev/null && docker compose up -d kt-witness" >/dev/null
fi

if [ "$WHAT" = all ] || [ "$WHAT" = workers ] || [ "$WHAT" = mac ]; then
  # This laptop. It runs the worker directly rather than in a container: it is
  # somebody's machine, and the whole point of the pacing is that it behaves
  # like a background job on it.
  echo "==> mac: build and restart"
  ( cd "$here" && go build -o bin/kt-worker ./cmd/kt-worker )
  pkill -f "bin/kt-worker -server" 2>/dev/null || true
  sleep 2
  ( cd "$here" && set -a && . ./secrets/work.env && set +a && \
    nohup ./bin/kt-worker \
      -server "${KT_WORK_SERVER:-$MAC_SERVER}" \
      -akd-origins "${KT_MAC_ORIGINS:-whatsapp.kt/v2}" \
      -name "$(hostname -s)" > worker.log 2>&1 < /dev/null & )
fi

if [ "$WHAT" = all ] || [ "$WHAT" = workers ] || [ "$WHAT" = gpu ]; then
  # The GPU box takes a cross-compiled binary rather than an image: it runs one
  # Go program with no Rust in it, so a container round trip buys nothing.
  echo "==> gpu-box: build, copy, restart"
  ( cd "$here" && GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
      -o /tmp/kt-worker-linux ./cmd/kt-worker )
  scp -q /tmp/kt-worker-linux "$GPU:~/kt-worker/kt-worker.new"

  # systemd where it is installed (deploy/gpu/kt-worker.service), and every
  # ssh bounded by a timeout either way.
  #
  # The fallback path is `setsid nohup ./kt-worker ... &` inside an ssh command,
  # and it HANGS: the backgrounded process inherits the ssh channel's file
  # descriptors, so ssh waits for an EOF that never arrives. The worker starts
  # fine; only the deploy is stuck, which is the worst shape for a bug like this
  # because everything downstream looks broken. Ten minutes of a deploy went
  # into that before it was understood, so the timeout is not belt and braces —
  # it is the difference between a bounded wait and a wedged script.
  if ssh -n -o ConnectTimeout=10 "$GPU" 'systemctl --user is-enabled kt-worker' >/dev/null 2>&1; then
    ssh -n -o ConnectTimeout=10 "$GPU" \
      'cd ~/kt-worker && mv kt-worker.new kt-worker && chmod +x kt-worker && \
       systemctl --user restart kt-worker'
  else
    echo "    (no systemd unit; using the nohup path — see deploy/gpu/kt-worker.service)"
    timeout 30 ssh -n -o ConnectTimeout=10 "$GPU" \
      'cd ~/kt-worker && pkill -f "^\./kt-worker " 2>/dev/null; sleep 3; \
       mv kt-worker.new kt-worker && chmod +x kt-worker && \
       set -a && . ./work.env && set +a && \
       setsid ./kt-worker -server "$KT_WORK_SERVER" -akd-origins "$KT_WORK_ORIGINS" \
         -name gpu-box < /dev/null > worker.log 2>&1 &' >/dev/null 2>&1 || true
  fi
fi

echo "==> settling"
sleep 12

echo "==> what came back:"
timeout 30 ssh -n "$HOST" 'cd ~/kt-witness && docker compose logs --since=30s kt-witness 2>&1 \
  | grep -E "worker connected|scratch space|level=ERROR" | tail -6' || true
echo "done. Logs: deploy/loki-tunnel.sh, then query Loki on 127.0.0.1:3100"
