# Stage 1: Build - Upgraded to 1.88 to meet dependency MSRV requirements
FROM rust:1.88-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/microclaw

# Copy the entire project repository
COPY . .

# Build the binary in release mode
RUN cargo build --release

# Stage 2: Run
FROM debian:bookworm-slim

# Install runtime certificates and libraries
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary
COPY --from=builder /usr/src/microclaw/target/release/microclaw /usr/local/bin/

# Copy necessary runtime directories
COPY --from=builder /usr/src/microclaw/web ./web
COPY --from=builder /usr/src/microclaw/skills ./skills
COPY --from=builder /usr/src/microclaw/scripts ./scripts

# Ensure the binary is executable
RUN chmod +x /usr/local/bin/microclaw

CMD ["microclaw"]
