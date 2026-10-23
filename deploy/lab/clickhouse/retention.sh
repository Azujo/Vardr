#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Stosuje retencję z pliku .env do istniejącej bazy (schemat w init/ działa
# tylko przy pierwszym starcie z pustym wolumenem). Bezpieczne do
# wielokrotnego uruchamiania. Użycie (na serwerze, w katalogu stosu):
#
#   ./clickhouse/retention.sh
#
# Zmienne: SIEM_EVENTS_TTL_DAYS (zdarzenia i kwarantanna),
#          SIEM_RAW_TTL_DAYS   (surowy XML, ≤ SIEM_EVENTS_TTL_DAYS).
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a

events=${SIEM_EVENTS_TTL_DAYS:-5}
raw=${SIEM_RAW_TTL_DAYS:-$events}
if ! [[ $events =~ ^[0-9]+$ && $raw =~ ^[0-9]+$ ]] || (( events < 1 || raw < 1 )); then
  echo "SIEM_EVENTS_TTL_DAYS and SIEM_RAW_TTL_DAYS must be numbers of days ≥ 1" >&2; exit 2
fi
if (( raw > events )); then
  echo "SIEM_RAW_TTL_DAYS ($raw) cannot be greater than SIEM_EVENTS_TTL_DAYS ($events)" >&2; exit 2
fi

ch() { docker compose exec -T clickhouse clickhouse-client --user "$CLICKHOUSE_ADMIN_USER" --password "$CLICKHOUSE_ADMIN_PASSWORD" --multiquery "$@"; }

ch <<SQL
ALTER TABLE siem.events MODIFY TTL toDateTime(ingested) + INTERVAL $events DAY;
ALTER TABLE siem.events MODIFY COLUMN raw String CODEC(ZSTD(3)) TTL toDateTime(ingested) + INTERVAL $raw DAY;
ALTER TABLE siem.quarantine MODIFY TTL toDateTime(ingested) + INTERVAL $events DAY;
SQL

# Tabela logowań korelacji (etap 8): ta sama retencja (udane logowania Windows – 1 dzień).
docker compose exec -T -e SIEM_EVENTS_TTL_DAYS="$events" clickhouse bash /docker-entrypoint-initdb.d/03-auth-events.sh

echo "Retention: events and quarantine $events days, raw XML $raw days."
ch -q "SELECT name, formatReadableSize(data_compressed_bytes) AS na_dysku FROM system.columns WHERE database = 'siem' AND table = 'events' ORDER BY data_compressed_bytes DESC LIMIT 4 FORMAT PrettyCompactMonoBlock"
