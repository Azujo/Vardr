#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Role bazy Saga – rozdzielenie uprawnień:
#
#   saga_admin     superużytkownik, tylko do administracji (żadna usługa go nie używa)
#   siem_api       panel: właściciel schematu public (konta, agenci, tokeny), bez
#                  superużytkownika; archiwum tylko czyta (rola urd_reader)
#   siem_archiver  archiwizator: właściciel schematu urd (spis archiwum NIS2)
#
# Przejęcie panelu nie daje więc możliwości zmiany ani usunięcia spisu
# archiwum (roadmapa, sekcja 6: oddzielenie administratora aplikacji od
# możliwości kasowania archiwum).
#
# Nowa instalacja: skrypt uruchamia obraz postgres przy pierwszym starcie.
# Istniejąca instalacja sprzed rozdzielenia (panel był superużytkownikiem
# utworzonym przy inicjalizacji bazy – takiej roli PostgreSQL nie pozwala
# odebrać uprawnień, więc zostaje przemianowana na saga_admin, a panel
# dostaje nową rolę):
#   docker compose stop api archiver
#   docker compose exec -T saga sh /docker-entrypoint-initdb.d/10-roles.sh
# Skrypt można uruchamiać wielokrotnie. Połączenia lokalne w kontenerze
# (gniazdo unix) nie wymagają hasła.
set -eu
: "${SAGA_DB_PASSWORD:?brak SAGA_DB_PASSWORD}" "${SAGA_ARCHIVER_PASSWORD:?brak SAGA_ARCHIVER_PASSWORD}"
: "${SAGA_DETECTOR_PASSWORD:?brak SAGA_DETECTOR_PASSWORD}"
admin="$POSTGRES_USER"
db="${POSTGRES_DB:-saga}"

# Kto jest superużytkownikiem z inicjalizacji (oid 10)?
boot=$(psql --no-psqlrc -tA --username "$admin" --dbname "$db" -c "SELECT rolname FROM pg_roles WHERE oid = 10" 2>/dev/null ||
  psql --no-psqlrc -tA --username siem_api --dbname "$db" -c "SELECT rolname FROM pg_roles WHERE oid = 10")
if [ "$boot" != "$admin" ]; then
  echo "renaming the superuser $boot -> $admin"
  psql --no-psqlrc -q -v ON_ERROR_STOP=1 --username "$boot" --dbname "$db" \
    -c "DROP ROLE IF EXISTS vardr_rename" -c "CREATE ROLE vardr_rename LOGIN SUPERUSER"
  psql --no-psqlrc -q -v ON_ERROR_STOP=1 --username vardr_rename --dbname "$db" \
    -c "ALTER ROLE \"$boot\" RENAME TO \"$admin\""
  psql --no-psqlrc -q -v ON_ERROR_STOP=1 --username "$admin" --dbname "$db" -c "DROP ROLE vardr_rename"
fi

psql -v ON_ERROR_STOP=1 --no-psqlrc --quiet --username "$admin" --dbname "$db" \
  -v admin_user="$admin" -v admin_pw="$POSTGRES_PASSWORD" -v db="$db" \
  -v api_pw="$SAGA_DB_PASSWORD" -v archiver_pw="$SAGA_ARCHIVER_PASSWORD" -v detector_pw="$SAGA_DETECTOR_PASSWORD" <<'SQL'
ALTER ROLE :"admin_user" PASSWORD :'admin_pw';

SELECT 'CREATE ROLE siem_api LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_api') \gexec
SELECT 'CREATE ROLE siem_archiver LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_archiver') \gexec
SELECT 'CREATE ROLE urd_reader NOLOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'urd_reader') \gexec
SELECT 'CREATE ROLE siem_detector LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'siem_detector') \gexec
ALTER ROLE siem_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'api_pw';
ALTER ROLE siem_archiver LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'archiver_pw';
ALTER ROLE siem_detector LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'detector_pw';
GRANT urd_reader TO siem_api;

-- Baza należy do administratora (właściciel bazy mógłby ją usunąć).
ALTER DATABASE :"db" OWNER TO :"admin_user";
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO siem_api, siem_archiver, siem_detector;

-- Schemat public i tabele panelu należą do panelu (po przemianowaniu
-- superużytkownika właścicielem był saga_admin). Sekwencje kolumn
-- przechodzą razem z tabelą.
ALTER SCHEMA public OWNER TO siem_api;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SELECT format('ALTER TABLE public.%I OWNER TO siem_api', c.relname)
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm')
    AND pg_get_userbyid(c.relowner) <> 'siem_api' \gexec

-- Schemat archiwum i jego obiekty należą do archiwizatora.
CREATE SCHEMA IF NOT EXISTS urd AUTHORIZATION siem_archiver;
ALTER SCHEMA urd OWNER TO siem_archiver;
SELECT format('ALTER TABLE urd.%I OWNER TO siem_archiver', tablename)
  FROM pg_tables WHERE schemaname = 'urd' AND tableowner <> 'siem_archiver' \gexec
REVOKE ALL ON SCHEMA urd FROM PUBLIC;
GRANT USAGE ON SCHEMA urd TO urd_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA urd TO urd_reader;
SELECT 'GRANT UPDATE (verify_requested_at, verify_requested_by) ON urd.archiver_state TO urd_reader'
  WHERE to_regclass('urd.archiver_state') IS NOT NULL \gexec

-- Schemat alertów (Gjallarhorn) należy do detektora; panel czyta i obsługuje
-- outbox (uprawnienia nadaje też migracja detektora).
CREATE SCHEMA IF NOT EXISTS gjallarhorn AUTHORIZATION siem_detector;
ALTER SCHEMA gjallarhorn OWNER TO siem_detector;
REVOKE ALL ON SCHEMA gjallarhorn FROM PUBLIC;
GRANT USAGE ON SCHEMA gjallarhorn TO siem_api;
GRANT SELECT ON ALL TABLES IN SCHEMA gjallarhorn TO siem_api;

-- Archiwizator czyta przypisania agentów do grup (wykluczenia grup z polityki
-- archiwum); tabele zakłada panel, więc grant także w jego migracji 005.
GRANT USAGE ON SCHEMA public TO siem_archiver;
SELECT 'GRANT SELECT (id, is_default) ON public.agent_groups TO siem_archiver'
  WHERE to_regclass('public.agent_groups') IS NOT NULL \gexec
SELECT 'GRANT SELECT (agent_id, group_id) ON public.agent_assignments TO siem_archiver'
  WHERE to_regclass('public.agent_assignments') IS NOT NULL \gexec
SQL
echo "Saga database roles ready: $admin (administration), siem_api (panel), siem_archiver (archive)"
