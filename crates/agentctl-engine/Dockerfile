# syntax=docker/dockerfile:1
# Builds the agentctl-engine Rust sidecar (behavioral scoring + EIP-712
# signature inspection over HTTP). NOT build-verified in this environment (no
# Docker daemon available at authoring time) — verify with `docker build`
# before relying on it. Build from the repo root:
#   docker build -f crates/agentctl-engine/Dockerfile -t agentctl-engine .

FROM rust:1.82-slim-bookworm AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
COPY crates/agentctl-engine/Cargo.toml crates/agentctl-engine/Cargo.lock ./
COPY crates/agentctl-engine/src src
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 1001 agentctl
COPY --from=build /app/target/release/agentctl-engine /usr/local/bin/agentctl-engine
USER agentctl

EXPOSE 8088
# Defaults to loopback-only (see main.rs) — set AGENTCTL_ENGINE_HOST=0.0.0.0 to
# accept connections from outside the container, and AGENTCTL_ENGINE_TOKEN to
# require Authorization: Bearer <token> on /score and /inspect/*.
ENV AGENTCTL_ENGINE_HOST=0.0.0.0
ENV AGENTCTL_ENGINE_PORT=8088
ENTRYPOINT ["/usr/local/bin/agentctl-engine"]
