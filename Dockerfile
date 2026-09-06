# Two builders, because verification lives in two languages: the witness core is
# Go, and AKD proof verification is only practical against facebook/akd in Rust.
#
#   docker build --platform linux/amd64 -t kt-witness .
#
# Note there is no apt-get anywhere. That is deliberate: apt's GPG verification
# fails under QEMU emulation ("at least one invalid signature was encountered"),
# so any apt step would break cross-platform builds. Avoiding it entirely is
# also just less to go wrong.

# Deliberately NOT $BUILDPLATFORM: this must produce a binary for the *target*
# platform. Building natively on the build host would silently copy, say, an
# arm64 binary into an amd64 image — which fails only at runtime, and only for
# tier B. On an amd64 host this stage is native and fast; cross-building from
# arm64 runs under emulation and is slow.
#
# No system packages are needed: the sidecar uses rustls and webpki-roots, so
# there is no OpenSSL to link and no CA bundle to install.
FROM rust:1-slim-bookworm AS rust-builder
WORKDIR /src
COPY rust/kt-akd-verify/Cargo.toml rust/kt-akd-verify/Cargo.lock ./
# Prime the dependency cache against a stub so a source-only change does not
# rebuild the akd tree, which is slow.
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release && rm -rf src
COPY rust/kt-akd-verify/src ./src
RUN touch src/main.rs && cargo build --release


# Go cross-compiles cheaply, so this stage runs natively and targets TARGETARCH.
FROM --platform=$BUILDPLATFORM golang:1.24-bookworm AS go-builder
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/kt-witness ./cmd/kt-witness
# kt-unblock probes the external preconditions the blocked TODO items wait on.
# Shipped in the image rather than left as a thing to run by hand, because a
# conclusion nobody revisits is exactly what it was written to prevent — and it
# had itself gone unscheduled since it was written.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/kt-unblock ./cmd/kt-unblock


# Distroless "cc", not "base": the Rust sidecar is dynamically linked and needs
# libgcc_s.so.1 for unwinding, which base-debian12 does not ship. With base the
# image builds and the witness runs — only the sidecar fails, at the moment it is
# first needed, in a log nobody is watching. Verified by executing the sidecar in
# the built image, which is worth doing rather than assuming.
#
# This layer also provides the CA bundle the Go binary reads (it is CGO-free and
# uses the system pool), and has no shell or package manager.
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=go-builder   /out/kt-witness                    /usr/local/bin/kt-witness
COPY --from=go-builder   /out/kt-unblock                    /usr/local/bin/kt-unblock
COPY --from=rust-builder /src/target/release/kt-akd-verify  /usr/local/bin/kt-akd-verify

# State lives here and must be a volume. The signing key IS our published
# identity, and the database is the record of what we have attested; losing
# either means coming back as a different, amnesiac party.
#
# The image runs as uid 65532, so the host directory must be writable by it:
#   chown -R 65532:65532 ./data
VOLUME /data
WORKDIR /data

EXPOSE 8080

# Tier B streams a ~284 MB proof to a temp file per verified epoch, so /tmp needs
# real space — run with --tmpfs /tmp:size=1g or a disk-backed mount.
ENV TMPDIR=/tmp

ENTRYPOINT ["/usr/local/bin/kt-witness"]
CMD ["-config", "/data/witness.json"]
