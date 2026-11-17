# Runs the whole workspace test suite as the image build. A failing test fails the
# build, and the build log holds the results. Used by Coolify; not a runtime image.
FROM rust:1.100.0-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake clang pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cargo test --workspace --no-fail-fast
