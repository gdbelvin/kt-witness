#!/bin/sh
# Fetch Proton's entire retained key-directory history for offline auditing.
#
# # Why one dump and five hundred diffs
#
# Proton publishes a full leaf dump per epoch (13.7 GB) and a diff between
# consecutive epochs (~7.5 MB). Downloading a dump per epoch would be about 6.9
# TB. Downloading the OLDEST retained dump plus every diff forward is ~17.5 GB,
# and reconstructs exactly the same 501 trees.
#
# # Why now rather than when it is needed
#
# Proton retains roughly ninety days and the floor advances about six epochs a
# day. Every epoch not fetched today is one nobody outside Proton can ever
# reconstruct again — the diff that reaches it stops being served, and the
# construction of that epoch becomes permanently unauditable by anyone. This is
# the one part of the work that expires.
#
# Also fetches each epoch's signed TreeHash into a manifest, so an offline
# rebuild has something to check against without going back to the network.
set -eu

OUT="${1:-/srv/proton-history}"
API="${API:-https://api.protonmail.ch}"
DUMPS="${DUMPS:-https://proton.me/kt}"

mkdir -p "$OUT/diffs"

# The floor moves, so ask rather than assume. StartEpochID is the oldest epoch
# still retained; below it nothing can be fetched.
tip=$(curl -sS -m 30 "$API/kt/v1/epochs" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Epochs"][0]["EpochID"])')
floor=$(curl -sS -m 30 "$API/kt/v1/epochs/$tip" | python3 -c 'import json,sys; print(json.load(sys.stdin)["StartEpochID"])')
echo "retained range: $floor..$tip ($((tip - floor + 1)) epochs)"
echo "$floor $tip" > "$OUT/range"

# Signed roots first: small, and without them the trees prove nothing.
echo "fetching epoch metadata..."
: > "$OUT/manifest.jsonl.tmp"
e=$floor
while [ "$e" -le "$tip" ]; do
  if [ ! -s "$OUT/meta.$e.json" ]; then
    curl -sS --fail -m 30 "$API/kt/v1/epochs/$e" -o "$OUT/meta.$e.json" || { echo "meta $e failed"; exit 1; }
    sleep 0.2   # someone else's production service
  fi
  python3 - "$OUT/meta.$e.json" "$e" >> "$OUT/manifest.jsonl.tmp" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(json.dumps({"epoch":int(sys.argv[2]),"tree_hash":d["TreeHash"],
                  "chain_hash":d.get("ChainHash",""),"start_epoch":d.get("StartEpochID")}))
PY
  e=$((e + 1))
done
mv "$OUT/manifest.jsonl.tmp" "$OUT/manifest.jsonl"
echo "manifest: $(wc -l < "$OUT/manifest.jsonl") epochs"

# The base tree: the oldest epoch still retained.
if [ ! -s "$OUT/epoch_tree_$floor.bin" ]; then
  echo "fetching base dump for $floor (~13.7 GB)..."
  curl -sS --fail --retry 3 -C - "$DUMPS/epoch.1.$floor" -o "$OUT/epoch_tree_$floor.bin.part"
  sz=$(stat -c%s "$OUT/epoch_tree_$floor.bin.part")
  [ $((sz % 68)) -eq 0 ] || { echo "base dump is $sz bytes, not a whole number of 68-byte leaves"; exit 1; }
  mv "$OUT/epoch_tree_$floor.bin.part" "$OUT/epoch_tree_$floor.bin"
fi
echo "base: $(stat -c%s "$OUT/epoch_tree_$floor.bin") bytes"

# Every diff forward.
echo "fetching diffs $((floor + 1))..$tip"
e=$((floor + 1))
got=0
while [ "$e" -le "$tip" ]; do
  f="$OUT/diffs/epoch.1.$e.diff"
  if [ ! -s "$f" ]; then
    # --fail matters more than it looks. Without it curl treats an HTTP error
    # as a successful transfer of the error page: this script once wrote an
    # 11 KB "Forbidden" HTML document to disk as epoch.1.6675.diff, and it sat
    # there looking like data until a replay twelve hours later tried to parse
    # it. --retry does not cover this; it retries transport failures, and a 403
    # is a perfectly successful HTTP conversation.
    if ! curl -sS --fail --retry 3 -m 600 "$DUMPS/epoch.1.$e.diff" -o "$f.part"; then
      rm -f "$f.part"
      echo "diff $e UNAVAILABLE — the epoch cannot be reconstructed by anyone without it"
      echo "$e" >> "$OUT/unavailable"
      e=$((e + 1))
      continue
    fi
    # A diff is a whole number of 69-byte records or it is not a diff. Checked
    # here, where it costs nothing, rather than in the replay.
    sz=$(stat -c%s "$f.part")
    if [ $((sz % 69)) -ne 0 ]; then
      rm -f "$f.part"
      echo "diff $e is $sz bytes, not a whole number of 69-byte records — refusing it"
      echo "$e" >> "$OUT/unavailable"
      e=$((e + 1))
      continue
    fi
    mv "$f.part" "$f"
    got=$((got + 1))
    sleep 0.1
  fi
  e=$((e + 1))
done
echo "diffs: $got fetched, $(ls "$OUT/diffs" | wc -l) present"
if [ -s "$OUT/unavailable" ]; then
  echo "UNAVAILABLE EPOCHS: $(tr "\n" " " < "$OUT/unavailable")"
  echo "  these cannot be reconstructed by any third party; the replay will have to"
  echo "  re-bootstrap from a later full dump and record the gap."
fi
du -sh "$OUT"
echo "done"
