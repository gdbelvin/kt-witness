#!/bin/sh
# Keep Proton's construction audit current, beside the GPU.
#
# # Why this is not on the witness
#
# One Proton rebuild is 41.8 billion SHA-256. On the witness that is about two
# hours and sixteen of its thirty-two cores; on the A10 it is sixty seconds. The
# witness was spending half its machine, for roughly half of every four-hour
# epoch, on work that finishes here before the kettle boils — while the AKD
# sweep, which has no GPU path at all because Meta and WhatsApp publish proofs
# rather than trees, waited for the cores.
#
# So the witness keeps no retained tree. This fetches what Proton has published
# since last time, replays it, and appends the verdicts to the same results file
# the witness already imports. Nothing new had to be built for that: it is the
# offline backfill run repeatedly with a moving target.
#
#   usage: follow-proton.sh [dir]        (default /srv/proton-history)
#
# Run it on a timer. Proton publishes every four hours and one epoch costs about
# ninety seconds, so anything under an hour keeps up with room to spare.
set -eu

OUT="${1:-/srv/proton-history}"
API="${API:-https://api.protonmail.ch}"
DUMPS="${DUMPS:-https://proton.me/kt}"
LOCK="$OUT/.follow.lock"

# One at a time. A second copy would fight the first over the retained tree, and
# the tree is the one thing here that must never be half-written.
if ! mkdir "$LOCK" 2>/dev/null; then
  echo "another follow is running ($LOCK); nothing to do"
  exit 0
fi
trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT INT TERM

have=$(ls "$OUT"/epoch_tree_*.bin 2>/dev/null | sed "s/.*epoch_tree_//;s/\.bin//" | sort -n | tail -1)
[ -n "$have" ] || { echo "no retained tree in $OUT; run fetch-proton-history.sh first"; exit 1; }

tip=$(curl -sS --fail -m 30 "$API/kt/v1/epochs" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["Epochs"][0]["EpochID"])')
echo "retained tree at $have, Proton is at $tip"
[ "$tip" -le "$have" ] && { echo "already current"; exit 0; }

# Metadata first: without the signed root there is nothing to check against, and
# a replay that cannot check is not an audit.
e=$((have + 1))
while [ "$e" -le "$tip" ]; do
  if [ ! -s "$OUT/meta.$e.json" ]; then
    curl -sS --fail -m 30 "$API/kt/v1/epochs/$e" -o "$OUT/meta.$e.json" || {
      echo "epoch $e metadata unavailable; stopping here rather than replaying blind"; break; }
    python3 - "$OUT/meta.$e.json" "$e" >> "$OUT/manifest.jsonl" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(json.dumps({"epoch":int(sys.argv[2]),"tree_hash":d["TreeHash"],
                  "chain_hash":d.get("ChainHash",""),"start_epoch":d.get("StartEpochID")}))
PY
  fi
  f="$OUT/diffs/epoch.1.$e.diff"
  if [ ! -s "$f" ]; then
    # --fail, because without it a 403 is written to disk as an 11 KB HTML
    # document that looks like a diff until something tries to parse it.
    if ! curl -sS --fail --retry 3 -m 600 "$DUMPS/epoch.1.$e.diff" -o "$f.part"; then
      rm -f "$f.part"
      echo "epoch $e diff unavailable — recorded, and the replay stops here"
      echo "$e" >> "$OUT/unavailable"
      break
    fi
    sz=$(stat -c%s "$f.part")
    if [ $((sz % 69)) -ne 0 ]; then
      rm -f "$f.part"
      echo "epoch $e diff is $sz bytes, not whole 69-byte records — refusing it"
      echo "$e" >> "$OUT/unavailable"
      break
    fi
    mv "$f.part" "$f"
  fi
  e=$((e + 1))
done

/usr/local/bin/kt-proton-backfill -dir "$OUT" -out "$OUT/backfill.jsonl"
