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

# The related-policy tests need two empty databases on the same server as the admin URL.
# The RLS test gets its own empty database too: the driver tests leave tables in
# falak_test, and the RLS test must not see them.
RUN set -eu; \
    base="${FALAK_TEST_PG_ADMIN_URL%/*}"; \
    for db in related_reads related_writes rls; do \
      if ! psql "$base/postgres" -tAc "SELECT 1 FROM pg_database WHERE datname='$db'" | grep -q 1; then \
        psql "$base/postgres" -c "CREATE DATABASE $db"; \
      fi; \
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
