# Two builders, because verification lives in two languages: the witness core is
# Go, and AKD proof verification is only practical against facebook/akd in Rust.
#
# Target is linux/amd64. Build with:
#   docker build --platform linux/amd64 -t kt-witness .

# Deliberately NOT $BUILDPLATFORM: this must produce a binary for the *target*
# platform. Building it natively on the build host would silently copy, say, an
# arm64 binary into an amd64 image. On an amd64 server this stage is native and
# fast; cross-building from arm64 runs under emulation and is slow.
FROM rust:1-slim-bookworm AS rust-builder
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY rust/kt-akd-verify/Cargo.toml rust/kt-akd-verify/Cargo.lock ./
# Prime the dependency cache against a stub so a source-only change does not
# rebuild the akd tree (which is slow).
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


FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 witness

COPY --from=go-builder  /out/kt-witness                         /usr/local/bin/kt-witness
COPY --from=rust-builder /src/target/release/kt-akd-verify      /usr/local/bin/kt-akd-verify

# State lives here and must be a volume: the signing key is our published
# identity, and the database is the record of what we have attested. Losing
# either means the witness comes back as a different, amnesiac party.
VOLUME /data
WORKDIR /data
USER witness

EXPOSE 8080

# Tier B streams a ~284 MB proof to a temp file per verified epoch, so /tmp needs
# real space — run with --tmpfs /tmp:size=1g or a disk-backed mount.
ENV TMPDIR=/tmp

ENTRYPOINT ["/usr/local/bin/kt-witness"]
CMD ["-config", "/data/witness.json"]
