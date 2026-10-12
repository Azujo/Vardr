#!/bin/bash
# Rejestracja agenta serwerowego na VM laboratorium – kolektora syslog
# (siem-collector) albo konektora API (siem-connector) – raz, po pierwszym
# „deploy.sh collector|connector”. Jak rejestracja agenta tokenem z panelu,
# tylko bez przeklejania tokenu: jednorazowy token (ważny 15 min, jedno
# użycie) powstaje na VM, w bazie jest wyłącznie jego skrót, tworzenie
# trafia do audytu panelu, a sam token nie jest nigdzie wypisywany.
#
#   deploy/lab/service-enroll.sh collector|connector [grupa agentów]
#
# Konektor w laboratorium łączy się z symulatorem Microsoft Graph
# (usługa entrasim): skrypt tworzy wspólny sekret aplikacji i ustawia
# adresy symulatora w connector.yaml.
set -euo pipefail
svc="${1:-}"
case "$svc" in
  collector) name="Kolektor syslog (VM)" ;;
  connector) name="Konektor API (VM)" ;;
  *) echo "użycie: $0 collector|connector [grupa]" >&2; exit 2 ;;
esac
host="${SIEM_LAB_HOST:-siem@192.168.88.98}"
key="${SIEM_LAB_KEY:-$HOME/.ssh/siem_lab}"
dir="${SIEM_LAB_DIR:-siem-lab}"
group="${2:-}"

ssh -i "$key" -o BatchMode=yes "$host" "SVC=$(printf %q "$svc") NAME=$(printf %q "$name") GROUP=$(printf %q "$group") bash -s $(printf %q "$dir")" <<'REMOTE'
set -euo pipefail
cd "$1"
if [ -f "$SVC/$SVC.yaml" ]; then
  echo "$SVC jest już zarejestrowany ($SVC/$SVC.yaml) – nic nie robię" >&2
  exit 1
fi
server=$(grep -o '^SIEM_PUBLIC_SERVER=[^ ]*' .env | cut -d= -f2)
[ -n "$server" ] || { echo "brak SIEM_PUBLIC_SERVER w .env" >&2; exit 1; }
mkdir -p "$SVC"
cp certs/ca.crt "$SVC/ca.crt"

token="hdt_$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
hash=$(printf '%s' "$token" | sha256sum | cut -d' ' -f1)
docker compose exec -T saga psql -U saga_admin -d saga -v ON_ERROR_STOP=1 -q -v hash="$hash" -v grp="$GROUP" -v name="$NAME" >/dev/null <<'SQL'
BEGIN;
SET LOCAL ROLE siem_api;
INSERT INTO enrollment_tokens (name, token_hash, profile, max_uses, expires_at, created_by, group_id)
SELECT :'name', :'hash', 'server', 1, now() + interval '15 minutes', 'service-enroll.sh',
       (SELECT id FROM agent_groups WHERE lower(name) = lower(:'grp'));
INSERT INTO audit_log (username, action, target, details)
VALUES ('service-enroll.sh', 'enroll_token_created', :'name',
        '{"profile": "server", "max_uses": 1, "valid": "15 min", "note": "token wygenerowany na VM dla agenta serwerowego"}');
COMMIT;
SQL

if [ "$SVC" = connector ]; then
  # Sekret aplikacji wspólny dla konektora i symulatora Graph (tylko laboratorium).
  umask 077
  openssl rand -hex 32 > connector/entra.secret
fi
docker compose build "$SVC" >/dev/null
docker compose run --rm --no-deps -T "$SVC" \
  enroll -server "$server:8443" -token "$token" -ca "/$SVC/ca.crt" -dir "/$SVC" </dev/null # bez stdin – inaczej wczyta resztę skryptu
unset token
if [ "$SVC" = connector ]; then
  # Laboratorium: symulator Microsoft Graph zamiast prawdziwego tenanta.
  sed -i -e 's|^  tenant_id: .*|  tenant_id: "lab"|' -e 's|^  client_id: .*|  client_id: "heimdall"|' \
    -e 's|^  # login_url / graph_url.*|  login_url: http://entrasim:8080\n  graph_url: http://entrasim:8080|' connector/connector.yaml
  docker compose up -d entrasim 2>&1 | grep -E 'Started|Error' || true
fi
docker compose up -d "$SVC" 2>&1 | grep -E 'Started|Error' || true
sleep 3
docker compose logs --tail 5 "$SVC"
REMOTE
