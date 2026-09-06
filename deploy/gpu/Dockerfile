# The GPU rebuild service: a CUDA binary and a very small HTTP server in front
# of it.
#
# Built here rather than on the witness host because this is the only thing in
# the project that needs a CUDA toolchain, and the witness image is distroless
# and CGO-free on purpose. Keeping them apart is the point: what runs beside the
# GPU is a hash function, and everything that could be wrong about a witness
# stays on the witness.

FROM nvidia/cuda:12.6.2-devel-ubuntu22.04 AS cuda-builder
WORKDIR /src
COPY cuda/kt-proton-gpu/main.cu .
# ARCH must match the card. sm_86 is Ampere (A10, A40, RTX 30xx).
ARG ARCH=sm_86
RUN nvcc -O3 -arch=${ARCH} -Xcompiler "-O3 -fopenmp" -o /out-kt-proton-gpu main.cu

FROM golang:1.24-bookworm AS go-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out-rootd ./cmd/kt-gpu-rootd

# The runtime image, not devel: no compiler beside the data.
FROM nvidia/cuda:12.6.2-runtime-ubuntu22.04
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=cuda-builder /out-kt-proton-gpu /usr/local/bin/kt-proton-gpu
COPY --from=go-builder   /out-rootd         /usr/local/bin/kt-gpu-rootd
ENTRYPOINT ["/usr/local/bin/kt-gpu-rootd"]
