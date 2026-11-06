# syntax=docker/dockerfile:1
# Build from the repository root: docker build -f apps/tvc-gateway/Dockerfile .
# crates/protocol inherits its edition and license from the root Cargo.toml.

FROM lukemathwalker/cargo-chef:latest-rust-1.98.0-bookworm@sha256:b1ed45bf65418f5daa5348b39f05ec6a6f5950996e0b797dbe38326d18d42e41 AS chef
WORKDIR /src/apps/tvc-gateway

FROM chef AS planner
COPY Cargo.toml /src/Cargo.toml
COPY crates/protocol /src/crates/protocol
COPY apps/tvc-gateway/Cargo.toml apps/tvc-gateway/Cargo.lock ./
COPY apps/tvc-gateway/src ./src
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY Cargo.toml /src/Cargo.toml
COPY crates/protocol /src/crates/protocol
COPY --from=planner /src/apps/tvc-gateway/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json

COPY apps/tvc-gateway/Cargo.toml apps/tvc-gateway/Cargo.lock ./
COPY apps/tvc-gateway/src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    cargo build --release --locked --bin tvc-gateway

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS run

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /app --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY --from=builder /src/apps/tvc-gateway/target/release/tvc-gateway /app/tvc-gateway
COPY apps/tvc-gateway/configs /app/configs
COPY packages/tvc-wallet/src/releases /app/releases
USER appuser

EXPOSE 8940
ENTRYPOINT ["/app/tvc-gateway"]
# One image serves either network: run it with --config /app/configs/mainnet.yaml for mainnet.
CMD ["--config", "/app/configs/devnet.yaml"]
