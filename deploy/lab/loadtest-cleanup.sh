#!/bin/bash
# Sprzątanie po teście obciążenia (siem-loadgen): zdarzenia, alerty, stan
# progów, agenci i heartbeaty agentów o podanym prefiksie.
#
#   cd ~/siem-lab && bash loadtest-cleanup.sh [prefiks ...]     (domyślnie agt-load-)
#
# Kolejność ma znaczenie (etap 8): najpierw zdarzenia w ClickHouse – inaczej
# silnik zapytań i korelacje przy kolejnych przebiegach (zakładka okien)
# odtworzą usunięte alerty z tych samych danych. Detektor jest zatrzymany na
# czas usuwania stanu progów (ma go też w pamięci). Archiwum Urd zostaje
# nietknięte (łańcuch hashy) – generator domyślnie i tak do niego nie trafia
# (SIEM_ARCHIVE_EXCLUDE_AGENTS).
set -euo pipefail
cd "$(dirname "$0")"
prefixes=("$@")
[[ ${#prefixes[@]} -eq 0 ]] && prefixes=(agt-load-)
for p in "${prefixes[@]}"; do
  # Prefiks prawdziwych agentów (np. „agt-”) usunąłby wszystko – wymagamy dłuższego.
  if [[ ! $p =~ ^[A-Za-z0-9_-]{5,}$ || $p == agt- ]]; then
    echo "BŁĄD: niepoprawny albo zbyt ogólny prefiks: $p" >&2
    exit 1
  fi
done
ch_cond=$(printf "startsWith(agent_id, '%s') OR " "${prefixes[@]}"); ch_cond=${ch_cond% OR }
pg_cond=$(printf "agent_id LIKE '%s%%' OR " "${prefixes[@]}"); pg_cond=${pg_cond% OR }
pg_agents=${pg_cond//agent_id/id}

ch() { docker compose exec -T clickhouse bash -c 'clickhouse client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" "$@"' _ "$@"; }
psql() { docker compose exec -T saga psql -U saga_admin -d saga -At -v ON_ERROR_STOP=1 "$@"; }

echo "zdarzenia w ClickHouse: $(ch -q "SELECT count() FROM siem.events WHERE $ch_cond")"
ch --mutations_sync 2 -q "ALTER TABLE siem.events DELETE WHERE $ch_cond"
ch --mutations_sync 2 -q "ALTER TABLE siem.quarantine DELETE WHERE $ch_cond"
if [[ $(ch -q "EXISTS TABLE siem.auth_events") == 1 ]]; then
  ch --mutations_sync 2 -q "ALTER TABLE siem.auth_events DELETE WHERE $ch_cond"
fi

docker compose stop detector >/dev/null
trap 'docker compose start detector >/dev/null; echo "detektor uruchomiony"' EXIT
psql <<SQL
BEGIN;
DELETE FROM gjallarhorn.alerts WHERE $pg_cond;
DELETE FROM gjallarhorn.threshold_events WHERE $pg_cond;
DELETE FROM agent_assignments WHERE $pg_cond;
DELETE FROM agents WHERE $pg_agents;
COMMIT;
SQL

# Ostatni heartbeat każdego agenta w strumieniu – bez tego panel po
# odtworzeniu stanu ze strumienia znów pokazałby agentów testowych.
# Prawdziwi agenci wyślą kolejny w ciągu minuty.
docker run --rm --network siem_default natsio/nats-box:0.18.1 nats -s nats://nats:4222 stream purge SIEM_HEARTBEATS -f >/dev/null
echo "gotowe: otwarte alerty $(psql -c "SELECT count(*) FROM gjallarhorn.alerts WHERE status <> 'closed'"), agenci $(psql -c "SELECT count(*) FROM agents")"
