# syntax=docker/dockerfile:1
FROM rust:1.100.0-slim-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY specifications ./specifications

RUN cargo build --release -p falak-cli

FROM debian:bookworm-20261027-slim AS runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/falak /usr/local/bin/falak

WORKDIR /app
COPY examples/notebook /app/notebook

ENV HOST=0.0.0.0
ENV PORT=8080

EXPOSE 8080

CMD ["falak", "serve", "/app/notebook", "--port", "8080"]
