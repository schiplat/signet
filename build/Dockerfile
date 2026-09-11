# syntax=docker/dockerfile:1

# NOTE: build context is the repository root (see build/docker-compose.yml),
# so all COPY source paths below are relative to the repo root, not to this file.

# --- Stage 1: build the Vue dashboard ------------------------------------
FROM node:20-alpine AS frontend
RUN corepack enable && corepack prepare pnpm@10 --activate
WORKDIR /src/dashboard
COPY dashboard/package.json dashboard/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY dashboard/ ./
RUN pnpm build

# --- Stage 2: compile the Rust backend ------------------------------------
# rust-embed embeds dashboard/dist at compile time, so the built frontend is
# copied in before `cargo build`. sqlx::migrate! also embeds the migrations dir.
FROM rust:1.96 AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY migrations ./migrations
COPY --from=frontend /src/dashboard/dist ./dashboard/dist
RUN cargo build --release -p signet

# --- Stage 3: minimal runtime ---------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home signet
WORKDIR /app
COPY --from=builder /src/target/release/signet /usr/local/bin/signet
# Persist JWT signing key + encryption key here (mounted volume in compose).
RUN mkdir -p /app/data && chown -R signet:signet /app
USER signet
EXPOSE 8443
ENV SIGNET_HTTP_BIND=0.0.0.0:8443
VOLUME ["/app/data"]
ENTRYPOINT ["signet"]
