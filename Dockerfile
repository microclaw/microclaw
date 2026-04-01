# syntax=docker/dockerfile:1

ARG NODE_VERSION=20
ARG RUST_VERSION=1.93.1

# Stage 1: Build embedded web assets so the binary does not depend on checked-in dist files.
FROM node:${NODE_VERSION}-bookworm-slim AS web-builder

WORKDIR /usr/src/microclaw/web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web ./
RUN npm run build

# Stage 2: Build tools
FROM rust:${RUST_VERSION}-slim-bookworm AS chef

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/microclaw

RUN cargo install cargo-chef --locked

# Stage 3: Prepare dependency recipe
FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 4: Build
FROM chef AS builder

COPY --from=planner /usr/src/microclaw/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
COPY --from=web-builder /usr/src/microclaw/web/dist ./web/dist

ENV MICROCLAW_SKIP_WEB_BUILD=1
RUN cargo build --release --locked --bin microclaw

# Stage 5: Run
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --home-dir /home/microclaw --uid 10001 --shell /usr/sbin/nologin microclaw

WORKDIR /app

COPY --from=builder /usr/src/microclaw/target/release/microclaw /usr/local/bin/
COPY --from=builder /usr/src/microclaw/skills ./skills
COPY --from=builder /usr/src/microclaw/scripts ./scripts

RUN mkdir -p /home/microclaw/.microclaw /app/tmp \
    && chown -R microclaw:microclaw /home/microclaw /app

ENV HOME=/home/microclaw
EXPOSE 10961

USER microclaw

ENTRYPOINT ["microclaw"]
CMD ["start"]
