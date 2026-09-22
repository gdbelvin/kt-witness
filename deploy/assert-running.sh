#!/bin/sh
# Ask the witness what it is, and fail if it is not what this checkout expects.
#
#   usage: deploy/assert-running.sh [ssh-host] [expected-commit]
#
# A deploy that ends by grepping thirty seconds of logs for errors tells you
# nothing about WHICH build came back. A stale layer, a pull that silently
# resolved to an older digest, a container that never recreated — all of those
# look like a healthy witness in the logs. This asks the running process for its
# commit and compares it with the one that was meant to be deployed.
#
# Over the tailnet to the host's own port rather than through the public name,
# so a cached answer from the CDN cannot stand in for the process being up.
set -eu

HOST="${1:-docker-services-ts}"
WANT="${2:-$(git -C "$(dirname "$0")/.." rev-parse --short HEAD)}"

# head runs here, not there. Closing the pipe on the remote side makes curl
# fail its write and say so — "curl: (23) Failure writing output to
# destination" printed beside a successful deploy, which is exactly the kind of
# noise that teaches people to ignore output.
LINE=$(ssh -n -o ConnectTimeout=10 "$HOST" 'curl -sS --max-time 10 http://127.0.0.1:8088/' | head -1)
echo "running: $LINE"

case "$LINE" in
  *"commit $WANT"*) echo "OK — serving $WANT" ;;
  *)
    echo "MISMATCH — expected commit $WANT, and that is not what answered." >&2
    echo "If CI has not finished publishing the image yet, wait and pull again." >&2
    exit 1
    ;;
esac
