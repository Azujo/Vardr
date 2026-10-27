#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Tabela logowań dla korelacji (etap 8). Korelacje („udane po nieudanych”,
# „nowy kraj”) czytały siem.events: co minutę wszystkie zdarzenia Windows
# z ostatnich 1,5 h, żeby znaleźć nieudane logowania – przy 7000 zdarzeń/s
# ok. 48 mln wierszy na przebieg, rosnąco z ruchem. Widok zmaterializowany
# odkłada przy zapisie tylko logowania (udane i nieudane, z osobą) do małej
# tabeli posortowanej po wyniku, zbiorze i czasie przyjęcia.
#
# Warunki logowań muszą być takie same jak authFailureSQL i authSuccessSQL
# w server/internal/detector/correlate.go (pilnuje tego test).
#
# Retencja: udane logowania Windows (najliczniejsze, 4624) – 1 dzień, wystarczy
# do okna korelacji; reszta jak zdarzenia (historia krajów). Partycja rozdziela
# te dwie grupy, więc wygasłe dane znikają całymi częściami.
#
# Obraz ClickHouse uruchamia skrypt przy pierwszym starcie. Istniejąca baza
# (instalator robi to przy każdej aktualizacji):
#   docker compose exec -T clickhouse bash /docker-entrypoint-initdb.d/03-auth-events.sh
# (bezpieczne do wielokrotnego uruchamiania; przy zakładaniu tabeli dopisuje
# logowania z siem.events z całej retencji, przy istniejącej – odtwarza widok
# z bieżącymi warunkami i dopisuje logowania z ostatniej godziny).
set -euo pipefail
ttl=${SIEM_EVENTS_TTL_DAYS:-5}
ch() { clickhouse client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery "$@"; }

select="SELECT event_id, timestamp, ingested,
    multiIf(((event_dataset = 'windows.security' AND event_code IN (4625, 4771))
        OR (event_dataset = 'azure.signinlogs' AND event_outcome = 'failure')
        OR (event_dataset = 'fortinet.fortigate' AND (event_action = 'ssl-login-fail' OR (event_action = 'login' AND event_outcome = 'failure')))
        OR (event_dataset = 'mikrotik.routeros' AND event_action = 'login' AND event_outcome = 'failure')
        OR (event_dataset IN ('linux.auth', 'pfsense.firewall', 'cisco.asa') AND event_action = 'login' AND event_outcome = 'failure')), 'failure',
      ((event_dataset = 'windows.security' AND event_code = 4624)
        OR (event_dataset = 'azure.signinlogs' AND event_outcome = 'success')
        OR (event_dataset = 'fortinet.fortigate' AND (event_action IN ('ssl-login', 'tunnel-up') OR (event_action = 'login' AND event_outcome = 'success')))
        OR (event_dataset = 'mikrotik.routeros' AND event_action = 'login' AND event_outcome = 'success')
        OR (event_dataset IN ('linux.auth', 'pfsense.firewall') AND event_action = 'login' AND event_outcome = 'success')
        OR (event_dataset = 'cisco.asa' AND event_action IN ('login', 'vpn-connect') AND event_outcome = 'success')), 'success', '') AS outcome,
    event_dataset, user_identity, user_name, host_name, agent_id,
    if(source_ip = toIPv6('::'), '', replaceRegexpOne(toString(source_ip), '^::ffff:', '')) AS ip,
    fields['source.geo.country_iso_code'] AS country, fields['source.geo.city_name'] AS city
  FROM siem.events
  WHERE user_identity != '' AND event_dataset IN ('windows.security', 'azure.signinlogs', 'fortinet.fortigate', 'mikrotik.routeros', 'linux.auth', 'pfsense.firewall', 'cisco.asa')
    AND outcome != ''"

if [[ $(ch -q "EXISTS TABLE siem.auth_events") == 1 ]]; then
  ch <<SQL
ALTER TABLE siem.auth_events MODIFY TTL addDays(toDateTime(ingested), if(event_dataset = 'windows.security' AND outcome = 'success', 1, $ttl));
DROP VIEW IF EXISTS siem.auth_events_mv;
CREATE MATERIALIZED VIEW siem.auth_events_mv TO siem.auth_events AS $select;
GRANT SELECT ON siem.auth_events TO siem_detector;
SQL
  # Chwila między usunięciem a założeniem widoku i nowe źródła logowań:
  # ostatnia godzina jeszcze raz (dubel korelacje pomijają – liczą po event_id).
  ch -q "INSERT INTO siem.auth_events $select AND ingested >= now() - INTERVAL 1 HOUR"
  echo "siem.auth_events already exists (retention $ttl days, view refreshed)"
  exit 0
fi

ch <<SQL
CREATE TABLE siem.auth_events
(
    event_id      String,
    timestamp     DateTime64(3, 'UTC'),
    ingested      DateTime64(3, 'UTC'),
    outcome       LowCardinality(String),
    event_dataset LowCardinality(String),
    user_identity LowCardinality(String),
    user_name     String,
    host_name     LowCardinality(String),
    agent_id      LowCardinality(String),
    ip            String,
    country       LowCardinality(String),
    city          LowCardinality(String)
)
ENGINE = ReplacingMergeTree(ingested)
PARTITION BY (toYYYYMMDD(ingested), event_dataset = 'windows.security' AND outcome = 'success')
ORDER BY (outcome, event_dataset, ingested, event_id)
TTL addDays(toDateTime(ingested), if(event_dataset = 'windows.security' AND outcome = 'success', 1, $ttl))
SETTINGS ttl_only_drop_parts = 1;

CREATE MATERIALIZED VIEW IF NOT EXISTS siem.auth_events_mv TO siem.auth_events AS $select;

GRANT SELECT ON siem.auth_events TO siem_detector;
SQL

# Logowania sprzed założenia tabeli (dubel z widokiem w tej samej chwili
# korelacje pomijają – liczą po event_id).
ch -q "INSERT INTO siem.auth_events $select AND ingested >= now() - INTERVAL $ttl DAY"
echo "siem.auth_events: $(ch -q "SELECT count() FROM siem.auth_events") sign-ins"
