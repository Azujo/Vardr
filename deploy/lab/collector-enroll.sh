#!/bin/bash
# Rejestracja kolektora syslog (siem-collector) na VM laboratorium – raz,
# po pierwszym „deploy.sh collector”. Jak rejestracja agenta tokenem z panelu,
# tylko bez przeklejania tokenu: jednorazowy token (ważny 15 min, jedno użycie)
# powstaje na VM, w bazie jest wyłącznie jego skrót, tworzenie trafia do
# audytu panelu, a sam token nie jest nigdzie wypisywany ani zapisywany.
#
#   deploy/lab/collector-enroll.sh [grupa agentów, domyślnie: grupa domyślna]
set -euo pipefail
host="${SIEM_LAB_HOST:-siem@192.168.88.98}"
key="${SIEM_LAB_KEY:-$HOME/.ssh/siem_lab}"
dir="${SIEM_LAB_DIR:-siem-lab}"
group="${1:-}"

ssh -i "$key" -o BatchMode=yes "$host" GROUP="$group" bash -s "$dir" <<'REMOTE'
set -euo pipefail
cd "$1"
if [ -f collector/collector.yaml ]; then
  echo "kolektor jest już zarejestrowany (collector/collector.yaml) – nic nie robię" >&2
  exit 1
fi
server=$(grep -o '^SIEM_PUBLIC_SERVER=[^ ]*' .env | cut -d= -f2)
[ -n "$server" ] || { echo "brak SIEM_PUBLIC_SERVER w .env" >&2; exit 1; }
mkdir -p collector
cp certs/ca.crt collector/ca.crt

token="hdt_$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
hash=$(printf '%s' "$token" | sha256sum | cut -d' ' -f1)
docker compose exec -T saga psql -U saga_admin -d saga -v ON_ERROR_STOP=1 -q -v hash="$hash" -v grp="$GROUP" >/dev/null <<'SQL'
BEGIN;
SET LOCAL ROLE siem_api;
INSERT INTO enrollment_tokens (name, token_hash, profile, max_uses, expires_at, created_by, group_id)
SELECT 'Kolektor syslog (VM)', :'hash', 'server', 1, now() + interval '15 minutes', 'collector-enroll.sh',
       (SELECT id FROM agent_groups WHERE lower(name) = lower(:'grp'));
INSERT INTO audit_log (username, action, target, details)
VALUES ('collector-enroll.sh', 'enroll_token_created', 'Kolektor syslog (VM)',
        '{"profile": "server", "max_uses": 1, "valid": "15 min", "note": "token wygenerowany na VM dla kolektora syslog"}');
COMMIT;
SQL

docker compose build collector >/dev/null
docker compose run --rm --no-deps -T collector \
  enroll -server "$server:8443" -token "$token" -ca /collector/ca.crt -dir /collector
unset token
docker compose up -d collector 2>&1 | grep -E 'Started|Error' || true
sleep 3
docker compose logs --tail 5 collector
REMOTE
