#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Zmiana klucza sortowania siem.events na (event_dataset,
# toStartOfHour(ingested), host_name, timestamp, event_id) w istniejącej
# instalacji (etap 8; nowe instalacje mają go od razu – init/01-schema.sh).
# Klucza sortowania nie da się zmienić w miejscu: nowa tabela, kopia partycjami,
# atomowa zamiana nazw. Writer jest w tym czasie zatrzymany – zdarzenia czekają
# w kolejce NATS i dopisują się po starcie (nic nie ginie).
#
#   cd ~/siem-lab && bash clickhouse/events-order.sh [prefiks_agentów_do_pominięcia]
#
# Opcjonalny prefiks (np. agt-load) pomija zdarzenia generatora obciążenia.
# Stara tabela zostaje jako siem.events_old – usuń ją po sprawdzeniu:
#   docker compose exec clickhouse clickhouse-client -q "DROP TABLE siem.events_old"
set -euo pipefail
cd "$(dirname "$0")/.."
skip=${1:-}
ch() { docker compose exec -T clickhouse bash -c 'clickhouse client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" "$@"' _ "$@"; }

key=$(ch -q "SELECT sorting_key FROM system.tables WHERE database = 'siem' AND name = 'events'")
if [[ $key == *"toStartOfHour(ingested)"* ]]; then
  echo "siem.events already has the new key: $key"
  exit 0
fi
if [[ -n $(ch -q "EXISTS TABLE siem.events_old" | grep 1 || true) ]]; then
  echo "ERROR: siem.events_old from a previous migration exists – remove it first" >&2
  exit 1
fi
echo "current key: $key"

ddl=$(ch -q "SHOW CREATE TABLE siem.events FORMAT TSVRaw")
ddl=${ddl/CREATE TABLE siem.events/CREATE TABLE siem.events_new}
ddl=$(sed -E 's/^ORDER BY .*/ORDER BY (event_dataset, toStartOfHour(ingested), host_name, timestamp, event_id)/' <<<"$ddl")
ch -q "DROP TABLE IF EXISTS siem.events_new"
ch -q "$ddl"

echo "stopping writer (events wait in NATS)"
docker compose stop writer >/dev/null
trap 'echo "starting writer"; docker compose start writer >/dev/null' EXIT

# Wiersze po terminie retencji nowa tabela odrzuca od razu (TTL) – nie liczą się.
ttl=$(grep -E '^SIEM_EVENTS_TTL_DAYS=' .env 2>/dev/null | cut -d= -f2 || true)
ttl=${ttl:-5}
filter="toDateTime(ingested) + INTERVAL $ttl DAY > now()"
[[ -n $skip ]] && filter="$filter AND NOT startsWith(agent_id, '$skip')"
for p in $(ch -q "SELECT DISTINCT partition_id FROM system.parts WHERE database = 'siem' AND table = 'events' AND active ORDER BY partition_id"); do
  ch --max_memory_usage=4000000000 -q "INSERT INTO siem.events_new SELECT * FROM siem.events WHERE _partition_id = '$p' AND $filter"
  want=$(ch -q "SELECT count() FROM siem.events WHERE _partition_id = '$p' AND $filter")
  got=$(ch -q "SELECT count() FROM siem.events_new WHERE _partition_id = '$p'")
  echo "partition $p: $got / $want"
  if [[ $got != "$want" ]]; then
    echo "ERROR: the row count does not match – table unchanged (check siem.events_new)" >&2
    exit 1
  fi
done

ch -q "EXCHANGE TABLES siem.events AND siem.events_new"
ch -q "RENAME TABLE siem.events_new TO siem.events_old"
echo "done: $(ch -q "SELECT sorting_key FROM system.tables WHERE database = 'siem' AND name = 'events'")"
echo "old table: siem.events_old (DROP TABLE after checking)"
