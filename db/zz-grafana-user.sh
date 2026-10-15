#!/bin/sh
# Creates grafana_ro, a read-only database user for Grafana.
#
# Runs automatically on the first start of hp-db (the "zz-" name makes it run
# AFTER init.sql, so the tables exist). It is safe to run again, e.g. on a
# database that already exists:
#   docker compose exec -T postgres sh /docker-entrypoint-initdb.d/zz-grafana-user.sh
#
# The password comes from GRAFANA_DB_PASSWORD (set in .env, passed in by
# docker-compose.yml).

psql -X -v ON_ERROR_STOP=1 -v pw="$GRAFANA_DB_PASSWORD" \
     -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<'SQL'
-- Create the role once, then always (re)set its password.
SELECT format('CREATE ROLE grafana_ro LOGIN PASSWORD %L', :'pw')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'grafana_ro')
\gexec
SELECT format('ALTER ROLE grafana_ro WITH LOGIN PASSWORD %L', :'pw')
\gexec

-- Read only: SELECT on the three tables, nothing else.
GRANT USAGE ON SCHEMA public TO grafana_ro;
GRANT SELECT ON events, ip_reputation, malware_samples TO grafana_ro;

-- Belt and braces: even if someone later grants more, every transaction this
-- user opens is read-only.
ALTER ROLE grafana_ro SET default_transaction_read_only = on;
SQL
