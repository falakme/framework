# Falak Office and Studio, one image, two programs. Build from the repository root:
#
#   docker build -f deploy/office/Dockerfile -t falak-office .
#
# The default command runs Office. Studio is the same image with another command:
#   falak-studio serve --config /config/studio.json --data /data/studio
FROM rust:1.100.0-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY crates ./crates
COPY specifications ./specifications
COPY examples ./examples
RUN cargo build --release --locked -p falak-office -p falak-studio

FROM debian:bookworm-20261027-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data falak \
 && mkdir -p /data && chown falak /data
COPY --from=build /src/target/release/falak-office /src/target/release/falak-studio /usr/local/bin/
USER falak
ENV FALAK_OFFICE_HOST=0.0.0.0 \
    FALAK_OFFICE_PORT=8788 \
    FALAK_OFFICE_DATA=/data \
    FALAK_STUDIO_HOST=0.0.0.0
VOLUME ["/data"]
EXPOSE 8788
HEALTHCHECK --interval=30s --timeout=3s CMD curl -fsS http://127.0.0.1:${FALAK_OFFICE_PORT}/readyz || exit 1
CMD ["falak-office", "serve"]
