# The GPU rebuild service

A narrow service on `docker-gpu` that rebuilds a transparency-log tree and
returns its root. Nothing else moves off the witness.

## What it is for

Between epochs, following Proton is a diff: ~7.5 MB changes ~108,000 of ~201
million leaves. But an incremental chain carries its own state forward. A
retained tree that is wrong stays wrong, and every later epoch still verifies
against the next diff. Only a rebuild from the leaves re-anchors it, and a full
rebuild costs ~42 billion SHA-256.

On the witness that is 14 minutes with its six workers, and hours when the AKD
sweep is competing for cores — measured at over four. On the A10 it is 105
seconds.

## The contract

**The service returns a root. It does not decide anything.**

It does not fetch the operator's signed root, does not compare, does not judge,
does not record. A root that disagrees with a signed one reads in this system as
the operator misbehaving, and that finding belongs to the witness, made on the
CPU from the Go implementation that is the specification.

On a mismatch the witness rebuilds on the CPU and lets that decide. A false
mismatch costs one CPU rebuild; a false match would require landing on the
signed hash by accident, which is not a failure mode hardware has.

The service also refuses, by filename, to rebuild a `.partial` (a half-written
tree, which rebuilds to a root matching nothing — indistinguishable at the far
end from equivocation) or a `.mismatch` (retained evidence, not a tree).

## The share

The two hosts are on the same LAN with 0.26 ms RTT, and **measured 266 MB/s**
between them, so reading the 13.7 GB tree costs roughly a minute. That is why
this reads the witness's own retained tree over NFS rather than re-downloading
Proton's published dump, which takes nine minutes and would check Proton rather
than checking us.

### You have to run these two — they need root on both machines

On **docker-services** (${KT_WITNESS_LAN_IP}), export the witness data read-only to
the GPU host and nothing else. Export the whole `data` directory rather than
just `proton-tree`, so that doing this for the other key-transparency trees
later needs no second export:

```sh
echo '/home/<user>/kt-witness/data ${KT_GPU_LAN_IP}(ro,sync,no_subtree_check,root_squash)' \
  | sudo tee -a /etc/exports
sudo exportfs -ra
```

On **docker-gpu** (${KT_GPU_LAN_IP}):

```sh
sudo mkdir -p /mnt/kt-witness
sudo mount -t nfs ${KT_WITNESS_LAN_IP}:/home/<user>/kt-witness/data /mnt/kt-witness
# to make it survive a reboot:
echo '${KT_WITNESS_LAN_IP}:/home/<user>/kt-witness/data /mnt/kt-witness nfs ro,soft,timeo=30,_netdev 0 0' \
  | sudo tee -a /etc/fstab
```

`ro` on both sides, twice over: the service must not be able to write into the
directory it audits.

## Run

```sh
docker compose -f deploy/gpu/compose.yaml up -d --build
curl -s http://${KT_GPU_LAN_IP}:8099/health
```

## Use

```sh
curl -sS -X POST http://${KT_GPU_LAN_IP}:8099/root \
  -H 'content-type: application/json' \
  -d '{"scheme":"proton-sparse-256","path":"proton-tree/epoch_tree_6730.bin"}'
```

```json
{"root":"b17a13…","leaves":201245751,"rounds":38,
 "upload_s":12.50,"kernel_s":45.71,"assemble_s":47.07,"total_s":105.29}
```

`scheme` has one value today. It exists because the reason to prove this out on
Proton is to do the same for the other key-transparency trees, and a caller
asking for one that is not implemented should get a refusal rather than a root.

One rebuild runs at a time — a 201M-leaf tree occupies about 20 GB of the card's
24 — and a second caller gets 503 with `Retry-After`.
