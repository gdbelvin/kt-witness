# One builder. Verification used to live in two languages — the witness core in
# Go, and AKD proof replay against facebook/akd in Rust — and the Rust half is
# gone: internal/akdtree does the same arithmetic in this process, an eighth of
# the CPU and a fraction of the memory, checked on every epoch against the roots
# each operator publishes.
#
#   docker build --platform linux/amd64 -t kt-witness .
#
# Note there is no apt-get anywhere. That is deliberate: apt's GPG verification
# fails under QEMU emulation ("at least one invalid signature was encountered"),
# so any apt step would break cross-platform builds. Avoiding it entirely is
# also just less to go wrong.

# Go cross-compiles cheaply, so this stage runs natively and targets TARGETARCH.
#
# The tag must keep up with go.mod: the toolchain in these images is pinned
# (GOTOOLCHAIN=local), so a go.mod that asks for more fails the build outright
# rather than downloading it. Adding gRPC raised the requirement to 1.25, and
# this line is the other half of that change.
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS go-builder
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/gomodcache,sharing=locked \
    GOMODCACHE=/gomodcache go mod download
COPY . .
# What software is actually running.
#
# The server is not a git checkout — source arrives there as a tarball — so the
# commit cannot be read at build time on the box where the build happens. It is
# baked in instead, from a .build-info file written by whoever ships the source
# (see deploy/RUNBOOK.md), with build args as an override for a direct build.
# Absent both, this reads "unknown", which is the honest answer and visibly not
# a version.
ARG GIT_COMMIT=""
ARG BUILD_DATE=""
#
# The compiler cache is mounted rather than rebuilt.
#
# Without it every deploy recompiles the whole module and its dependencies from
# nothing, because `COPY . .` invalidates the layer whenever any file changes —
# which on a deploy is always. gRPC, protobuf and blake3 do not change between
# one edit and the next, and compiling them again is the bulk of this stage.
#
# sharing=locked rather than the default: two builds at once would otherwise
# write the same cache concurrently, and the Go build cache is not safe under
# that.
RUN --mount=type=cache,target=/gocache,sharing=locked \
    --mount=type=cache,target=/gomodcache,sharing=locked \
    COMMIT="${GIT_COMMIT:-$(sed -n 's/^commit=//p' .build-info 2>/dev/null)}"; \
    BUILT="${BUILD_DATE:-$(sed -n 's/^date=//p' .build-info 2>/dev/null)}"; \
    GOCACHE=/gocache GOMODCACHE=/gomodcache \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w \
      -X main.gitCommit=${COMMIT:-unknown} \
      -X main.buildDate=${BUILT:-unknown}" \
    -o /out/kt-witness ./cmd/kt-witness
# kt-unblock probes the external preconditions the blocked TODO items wait on.
# Shipped in the image rather than left as a thing to run by hand, because a
# conclusion nobody revisits is exactly what it was written to prevent — and it
# had itself gone unscheduled since it was written.
RUN --mount=type=cache,target=/gocache,sharing=locked \
    --mount=type=cache,target=/gomodcache,sharing=locked \
    GOCACHE=/gocache GOMODCACHE=/gomodcache \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/kt-unblock ./cmd/kt-unblock


# Distroless "static", not "cc".
#
# It was "cc" because the Rust sidecar was dynamically linked and needed
# libgcc_s.so.1 for unwinding. Nothing in this image is dynamically linked any
# more: the Go binaries are CGO-free. "static" still carries the CA bundle they
# read for the system pool, and has no shell, no package manager and no libc.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=go-builder   /out/kt-witness                    /usr/local/bin/kt-witness
COPY --from=go-builder   /out/kt-unblock                    /usr/local/bin/kt-unblock

# State lives here and must be a volume. The signing key IS our published
# identity, and the database is the record of what we have attested; losing
# either means coming back as a different, amnesiac party.
#
# The image runs as uid 65532, so the host directory must be writable by it:
#   chown -R 65532:65532 ./data
VOLUME /data
WORKDIR /data

EXPOSE 8080

# Nothing writes a proof to disk any more. Tier B used to stream each ~284 MB
# proof to a temp file, because the Rust sidecar was a separate process reached
# through a pipe; that needed a sized /tmp, and the sizing caused two outages the
# day a widened pool outgrew it. The Go verifier holds the proof in memory, so no
# tmpfs is required. TMPDIR=/tmp is already Go's default on Linux, so the line
# below changes nothing; it is kept only so the choice is visible.
ENV TMPDIR=/tmp

ENTRYPOINT ["/usr/local/bin/kt-witness"]
CMD ["-config", "/data/witness.json"]
