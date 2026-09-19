#!/bin/sh
# Ship, build, restart, and say what happened — the whole inner loop, once.
#
#   usage: deploy/redeploy.sh [witness|mac|gpu|workers|all]   (default: all)
#
#   witness  the server: ship the config, pull the image, recreate the container
#            KT_WITNESS_TAG=sha-abc1234 (or 0.1.1) pins a new image first;
#            unset, the server keeps the tag already in its .env
#   mac      this laptop's worker, rebuilt and restarted in place
#   gpu      the GPU box's worker — NOT part of "all", see below
#   workers  the workers that are part of "all" (just the mac)
#   all      the witness and the mac
#
# The GPU box is deliberately not in "all". It is a GPU machine and AKD
# verification does not use a GPU: the ratio test in docs/gpu_notes.md put
# hashing at 6-7% of a verification's runtime, which caps a perfect GPU port at
# 1.47x, so there is nothing to move onto the card. Running the worker there
# spent the box's CPUs on work the witness is not short of — it sat at a load
# average of 1.5 on 40 cores, bound entirely on downloading Meta's 284 MB
# proofs, which every machine here shares one connection for. Start it by hand
# if the witness ever becomes CPU-bound rather than bandwidth-bound.
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
  # The server no longer builds. The image is built and attested on GitHub
  # from pushed code (.github/workflows/release.yml); what ships here is the
  # compose file and the config, and the tag that says which image to run.
  echo "==> witness: ship config"
  "$here/deploy/ship.sh" "$HOST" >/dev/null

  # The tag lives in the server's .env, which is gitignored and never shipped.
  # Pin it from here when asked, so a deploy is one command with the tag in
  # it, and the .env stays the record of what is running.
  if [ -n "${KT_WITNESS_TAG:-}" ]; then
    echo "==> witness: pin KT_WITNESS_TAG=$KT_WITNESS_TAG"
    ssh -n "$HOST" "cd ~/kt-witness && touch .env && \
      if grep -q '^KT_WITNESS_TAG=' .env; then \
        sed -i 's|^KT_WITNESS_TAG=.*|KT_WITNESS_TAG=$KT_WITNESS_TAG|' .env; \
      else echo 'KT_WITNESS_TAG=$KT_WITNESS_TAG' >> .env; fi"
  fi
  TAG=$(ssh -n "$HOST" "cd ~/kt-witness && sed -n 's/^KT_WITNESS_TAG=//p' .env 2>/dev/null" || true)
  [ -n "$TAG" ] || { echo "no KT_WITNESS_TAG on $HOST; pass one: KT_WITNESS_TAG=sha-abc1234 $0 witness" >&2; exit 1; }

  echo "==> witness: pull $TAG and restart"
  ssh -n "$HOST" "cd ~/kt-witness && docker compose pull -q kt-witness && docker compose up -d kt-witness" >/dev/null
fi

if [ "$WHAT" = all ] || [ "$WHAT" = workers ] || [ "$WHAT" = mac ]; then
  # This laptop. It runs the worker directly rather than in a container: it is
  # somebody's machine, and the whole point of the pacing is that it behaves
  # like a background job on it.
  echo "==> mac: build and restart"
  ( cd "$here" && go build -o bin/kt-worker ./cmd/kt-worker )
  pkill -f "bin/kt-worker -server" 2>/dev/null || true
  sleep 2
  # Every descriptor closed on the subshell itself, not just on the worker.
  #
  # Redirecting only the worker is not enough: the subshell inherits this
  # script's stdout, and when that is a pipe — `redeploy.sh | tail`, which is
  # how anyone runs it — the reader waits for an EOF that the still-running
  # worker is holding open. The script finishes and appears to hang. It is the
  # same mistake as the ssh one, a process boundary closer to home.
  ( cd "$here" && set -a && . ./secrets/work.env && set +a && \
    nohup ./bin/kt-worker \
      -server "${KT_WORK_SERVER:-$MAC_SERVER}" \
      -akd-origins "${KT_MAC_ORIGINS:-whatsapp.kt/v2}" \
      -name "${KT_MAC_NAME:-$(hostname -s)}" \
      -pprof "${KT_MAC_PPROF:-127.0.0.1:6060}" >> worker.log 2>&1 & \
  ) < /dev/null > /dev/null 2>&1
fi

if [ "$WHAT" = gpu ]; then
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
