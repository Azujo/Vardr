#!/bin/bash
# Usunięcie zdarzeń generatora z dziennej partycji siem.events przez
# przepisanie prawdziwych zdarzeń – po dużym teście obciążenia (dziesiątki
# milionów wierszy) mutacja DELETE z loadtest-cleanup.sh przekracza pamięć
# ClickHouse. Prawdziwe zdarzenia trafiają do tabeli pomocniczej, partycja
# jest usuwana i wypełniana z powrotem (porównanie liczby wierszy – przy
# niezgodności nic nie jest usuwane). Writer jest na ten czas zatrzymany
# (zdarzenia czekają w NATS). Potem: bash loadtest-cleanup.sh.
#
#   cd ~/siem-lab && bash loadtest-droppart.sh 20261017
set -euo pipefail
cd "$(dirname "$0")"
P=${1:?partycja, np. 20261015}
[[ $P =~ ^[0-9]{8}$ ]] || { echo "partycja to data RRRRMMDD" >&2; exit 2; }
ch() { docker compose exec -T clickhouse bash -c 'clickhouse client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" "$@"' _ "$@"; }

ch -q "KILL MUTATION WHERE database = 'siem' AND table = 'events' AND NOT is_done" >/dev/null || true
docker compose stop writer >/dev/null 2>&1
trap 'docker compose start writer >/dev/null 2>&1; echo "writer uruchomiony"' EXIT

cond="_partition_id = '$P' AND NOT startsWith(agent_id, 'agt-load-') AND NOT startsWith(agent_id, 'agt-arch-')"
want=$(ch -q "SELECT count() FROM siem.events WHERE $cond")
echo "prawdziwe zdarzenia w partycji $P: $want"
ch -q "DROP TABLE IF EXISTS siem.events_keep"
ch -q "CREATE TABLE siem.events_keep AS siem.events"
ch -q "INSERT INTO siem.events_keep SELECT * FROM siem.events WHERE $cond"
got=$(ch -q "SELECT count() FROM siem.events_keep")
echo "przeniesione: $got"
if [[ $got != "$want" ]]; then echo "BŁĄD: liczby się nie zgadzają – nic nie usuwam" >&2; exit 1; fi
ch -q "ALTER TABLE siem.events DROP PARTITION '$P'"
ch -q "INSERT INTO siem.events SELECT * FROM siem.events_keep"
echo "po: $(ch -q "SELECT count(), countIf(startsWith(agent_id, 'agt-load-')) FROM siem.events WHERE _partition_id = '$P'")"
ch -q "DROP TABLE siem.events_keep"
