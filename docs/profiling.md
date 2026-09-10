# Profiling the witness

`pprof_listen` in the config enables `net/http/pprof` on its own socket. It is
off unless named, and the port is left unpublished in compose, so it reaches the
host and nowhere else — verified: 404 over the tailnet, port closed, 200 from
the host.

```
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' kt-witness-kt-witness-1)
curl -s "http://$IP:6060/debug/pprof/profile?seconds=30" -o /tmp/cpu.pprof
go tool pprof -top /tmp/cpu.pprof     # no Go toolchain on the server; copy it off
```

## What the first profile corrected

The CPU split had been reasoned about from `ps` output: a main process at 563%
was attributed to Proton's tree rebuild, and Proton's hashing was capped at four
cores on that basis. Total CPU dropped by 5.8 cores, which corroborated the
guess — but corroboration is not measurement, and the profile shows the
attribution was only half right.

30-second profile, 8 Rust sidecar workers, Proton replaying history:

```
53.25%  internal/runtime/syscall.Syscall6
18.39%  runtime.memmove
53.64%  (cum) proton.ApplyDiff
43.33%  (cum) bufio.(*Writer).Write
```

The Go process's own CPU is dominated by **writing**, not hashing. Proton's
rebuild has two distinct phases and they have different costs:

- `ApplyDiff` — merges the published diff into a new 13.6 GB tree file. I/O
  bound: syscalls and memmove, effectively single-threaded through one
  `bufio.Writer`. **This is what was running.**
- `TreeRootParallel` — hashes the merged tree. CPU bound, and the phase the
  four-core cap actually governs.

So the cap was right, and the reasoning that produced it named the wrong phase.
The 563% observed earlier was the hashing phase; the profile happened to catch
the writing one.

The other half of the correction: the whole Go process accounted for ~0.76 cores
of the 30.2 in use. **Verification did not appear in that profile at all** — the
AKD replays ran in separate `kt-akd-verify` processes, so a Go profile could
never show them, and `ps` and the governor's own metrics were the only
instruments for that half of the machine.

That blind spot is gone. AKD replay is `internal/akdtree`, in this process, so a
profile taken now covers verification too — the larger consumer the profiler
previously could not reach. Read the split above as the record of what the first
profile corrected, not as the shape of a profile today.

## Goroutines

Flat at 131-132 across a minute under load, which is the check that matters
after moving the history sweep to a staged pipeline: a leak there would show as
monotonic growth.
