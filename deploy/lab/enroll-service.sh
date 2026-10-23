#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Rejestracja agenta serwerowego stosu – kolektora syslog (siem-collector)
# albo konektora API (siem-connector) – raz, na serwerze, w katalogu stosu.
# Jak rejestracja agenta tokenem z panelu, tylko bez przeklejania tokenu:
# jednorazowy token (ważny 15 min, jedno użycie) powstaje tutaj, w bazie
# jest wyłącznie jego skrót, tworzenie trafia do audytu panelu, a sam token
# nie jest nigdzie wypisywany.
#
#   ./enroll-service.sh collector|connector [agent group]
#
# Usługa zostaje dopisana do COMPOSE_PROFILES w .env (start ze stosem).
# VARDR_LAB_ENTRASIM=1 (laboratorium): konektor łączy się z symulatorem
# Microsoft Graph (usługa entrasim) zamiast prawdziwego tenanta.
set -euo pipefail
cd "$(dirname "$0")"
SVC="${1:-}"
# Nazwa tokenu w panelu – w języku systemu (ustawienie w panelu).
syslang=$(docker compose exec -T saga psql -U saga_admin -d saga -At -c "SELECT language FROM system_language" </dev/null 2>/dev/null || true)
case "$SVC" in
  collector) NAME="Kolektor syslog"; [ "$syslang" = en ] && NAME="Syslog collector" ;;
  connector) NAME="Konektor API"; [ "$syslang" = en ] && NAME="API connector" ;;
  *) echo "usage: $0 collector|connector [group]" >&2; exit 2 ;;
esac
GROUP="${2:-}"

if [ -f "$SVC/$SVC.yaml" ]; then
  echo "$SVC is already enrolled ($SVC/$SVC.yaml) – doing nothing" >&2
  exit 1
fi
env_get() { sed -n "s/^$1=//p" .env | tail -1; }
server=$(env_get SIEM_PUBLIC_SERVER)
[ -n "$server" ] || { echo "no SIEM_PUBLIC_SERVER in .env" >&2; exit 1; }
port=$(env_get VARDR_INGEST_PORT)
mkdir -p "$SVC"
cp certs/ca.crt "$SVC/ca.crt"
# Katalog należy do użytkownika usług stosu (gdy skrypt działa jako root).
if [ "$(id -u)" = 0 ]; then
  chown -R "$(env_get VARDR_UID):$(env_get VARDR_GID)" "$SVC" 2>/dev/null || true
fi

token="hdt_$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
hash=$(printf '%s' "$token" | sha256sum | cut -d' ' -f1)
docker compose exec -T saga psql -U saga_admin -d saga -v ON_ERROR_STOP=1 -q -v hash="$hash" -v grp="$GROUP" -v name="$NAME" >/dev/null <<'SQL'
BEGIN;
SET LOCAL ROLE siem_api;
INSERT INTO enrollment_tokens (name, token_hash, profile, max_uses, expires_at, created_by, group_id)
SELECT :'name', :'hash', 'server', 1, now() + interval '15 minutes', 'enroll-service.sh',
       (SELECT id FROM agent_groups WHERE lower(name) = lower(:'grp'));
INSERT INTO audit_log (username, action, target, details)
VALUES ('enroll-service.sh', 'enroll_token_created', :'name',
        '{"profile": "server", "max_uses": 1, "valid": "15 min", "note": "token generated on the server for a server agent"}');
COMMIT;
SQL

if [ "$SVC" = connector ] && [ "${VARDR_LAB_ENTRASIM:-}" = 1 ]; then
  # Sekret aplikacji wspólny dla konektora i symulatora Graph (tylko laboratorium).
  (umask 077 && openssl rand -hex 32 > connector/entra.secret)
fi
docker compose build "$SVC" >/dev/null
docker compose run --rm --no-deps -T "$SVC" \
  enroll -server "$server:${port:-8443}" -token "$token" -ca "/$SVC/ca.crt" -dir "/$SVC" </dev/null # bez stdin – inaczej wczyta resztę skryptu
unset token

# Start razem ze stosem (profil usługi w pliku stosu instalacji).
profiles=$(env_get COMPOSE_PROFILES)
if [[ ",$profiles," != *",$SVC,"* ]]; then
  sed -i '/^COMPOSE_PROFILES=/d' .env
  echo "COMPOSE_PROFILES=${profiles:+$profiles,}$SVC" >> .env
fi

if [ "$SVC" = connector ]; then
  if [ "${VARDR_LAB_ENTRASIM:-}" = 1 ]; then
    sed -i -e 's|^  tenant_id: .*|  tenant_id: "lab"|' -e 's|^  client_id: .*|  client_id: "vardr"|' \
      -e 's|^  # login_url / graph_url.*|  login_url: http://entrasim:8080\n  graph_url: http://entrasim:8080|' connector/connector.yaml
    docker compose up -d entrasim 2>&1 | grep -E 'Started|Error' || true
  else
    echo "Connector enrolled. Fill in tenant_id and client_id of the Entra ID application"
    echo "in $PWD/connector/connector.yaml, save the application secret in $PWD/connector/entra.secret"
    echo "(owner only: chmod 600), then: docker compose up -d connector"
    exit 0
  fi
fi
docker compose up -d "$SVC" 2>&1 | grep -E 'Started|Error' || true
sleep 3
docker compose logs --tail 5 "$SVC"
