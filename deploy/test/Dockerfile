# Runs the whole workspace test suite as the image build. A failing test fails the
# build, and the build log holds the results. Used by Coolify; not a runtime image.
FROM rust:1.100.0-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake clang pkg-config postgresql-client \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Coolify passes build-time variables as build args. Declare the ones the
# PostgreSQL tests read; without ARG, Docker does not expose them to RUN.
ARG DATABASE_URL
ARG FALAK_TEST_PG_ADMIN_URL
ARG FALAK_TEST_PG_URL

# These tests need empty databases on the same server as the admin URL. The database
# server outlives each build, so drop and recreate them every time: rows left by one
# build would break the next one. The RLS test gets its own database too, because the
# driver tests leave tables in falak_test.
RUN set -eu; \
    base="${FALAK_TEST_PG_ADMIN_URL%/*}"; \
    for db in related_reads related_writes rls; do \
      psql "$base/postgres" -q -c "DROP DATABASE IF EXISTS $db WITH (FORCE)"; \
      psql "$base/postgres" -q -c "CREATE DATABASE $db"; \
    done

# Keep the full log in the image layer. Print the panic lines last, so the short
# tail Coolify shows in its deployment summary carries the failures.
RUN set +e; \
    export FALAK_TEST_PG_ADMIN_URL="${FALAK_TEST_PG_ADMIN_URL%/*}/rls"; \
    cargo test --workspace --no-fail-fast > /tmp/test.log 2>&1; \
    status=$?; \
    grep -h -A1 "panicked at" /tmp/test.log | tail -16; \
    grep -h "FAILED\|failed:" /tmp/test.log | tail -8; \
    exit $status
