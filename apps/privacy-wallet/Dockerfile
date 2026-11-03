FROM rust:1.98-alpine3.24@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS build

# The network whose signed prover policy the image accepts: devnet or mainnet.
ARG SPR_NETWORK
ENV SPR_NETWORK=${SPR_NETWORK}
ENV RUSTFLAGS='-C target-feature=+crt-static'
ENV OPENSSL_STATIC='1'
ENV CARGOFLAGS='--target x86_64-unknown-linux-musl --locked --release --package zolana-tvc-privacy-wallet --bin zolana-tvc-privacy-wallet'
ENV RELEASE_DIR='/src/target/x86_64-unknown-linux-musl/release'

RUN apk add --no-cache \
    openssl-dev=3.5.9-r0 \
    openssl-libs-static=3.5.9-r0 \
    pkgconf=2.5.1-r0

ADD . /src/
WORKDIR /src/

RUN cargo fetch --locked
RUN --network=none <<-EOF
    set -eu
    case "${SPR_NETWORK}" in devnet|mainnet) ;; *) echo "--build-arg SPR_NETWORK=devnet|mainnet" >&2; exit 1 ;; esac
    cargo build ${CARGOFLAGS}
    mkdir -p /rootfs
    mv ${RELEASE_DIR}/zolana-tvc-privacy-wallet /rootfs/tvc_app
    sha256sum /rootfs/tvc_app | awk '{print "SHA256=" $1}'
EOF

FROM stagex/core-busybox:1.36.1@sha256:cac5d773db1c69b832d022c469ccf5f52daf223b91166e6866d42d6983a3b374 AS package
COPY --from=build /rootfs/. /

LABEL org.opencontainers.image.title="Zolana TVC Privacy Wallet" \
      org.opencontainers.image.description="Attested privacy wallet with enclave-held keys and an external-prover spend path" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

RUN sha256sum /tvc_app | awk '{print "SHA256=" $1}'
