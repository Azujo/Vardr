#!/bin/bash
# Schemat bazy SIEM (roadmapa, sekcja 15a). Uruchamiany przez obraz
# ClickHouse przy pierwszym starcie (pusty wolumen danych).
set -euo pipefail

ch() { clickhouse client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery "$@"; }

ch <<SQL
CREATE DATABASE IF NOT EXISTS siem;

-- Znormalizowane zdarzenia. Partycje i retencja liczone od czasu przyjęcia
-- (ingested), żeby zaległe zdarzenia z wielu dni nie tworzyły setek
-- partycji w jednym INSERT. ReplacingMergeTree usuwa duplikaty przy scalaniu.
CREATE TABLE IF NOT EXISTS siem.events
(
    timestamp            DateTime64(3, 'UTC'),
    ingested             DateTime64(3, 'UTC'),
    event_id             String,
    agent_id             LowCardinality(String),
    event_dataset        LowCardinality(String),
    event_code           UInt32,
    event_provider       LowCardinality(String),
    event_action         LowCardinality(String),
    event_outcome        LowCardinality(String),
    host_name            LowCardinality(String),
    user_name            String,
    user_domain          LowCardinality(String),
    source_ip            IPv6,
    process_name         String,
    process_command_line String CODEC(ZSTD(3)),
    message              String CODEC(ZSTD(3)),
    fields               Map(LowCardinality(String), String) CODEC(ZSTD(3)),
    -- Surowy XML ma własną retencję (SIEM_RAW_TTL_DAYS ≤ SIEM_EVENTS_TTL_DAYS):
    -- to ok. połowa miejsca, a pola znormalizowane zostają do końca retencji
    -- zdarzeń (roadmapa, zał. E, W2).
    raw                  String CODEC(ZSTD(3)) TTL toDateTime(ingested) + INTERVAL ${SIEM_RAW_TTL_DAYS} DAY,
    truncated            Bool,
    parser_version       LowCardinality(String),
    time_quality         LowCardinality(String),
    -- Etap 7a: osoba stojąca za kontem (ten sam klucz w AD, Entra, na VPN).
    user_identity        LowCardinality(String) DEFAULT '',

    INDEX idx_user    user_name TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_ip      source_ip TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_raw     raw       TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    INDEX idx_message message   TYPE tokenbf_v1(8192, 3, 0) GRANULARITY 4,
    -- Silnik zapytań detekcji czyta zdarzenia po czasie przyjęcia.
    INDEX idx_ingested ingested TYPE minmax GRANULARITY 1
)
ENGINE = ReplacingMergeTree(ingested)
PARTITION BY toYYYYMMDD(ingested)
ORDER BY (event_dataset, host_name, timestamp, event_id)
TTL toDateTime(ingested) + INTERVAL ${SIEM_EVENTS_TTL_DAYS} DAY
SETTINGS ttl_only_drop_parts = 1;

-- Zdarzenia, których nie udało się znormalizować (oryginał + powód).
CREATE TABLE IF NOT EXISTS siem.quarantine
(
    ingested DateTime64(3, 'UTC'),
    agent_id LowCardinality(String),
    event_id String,
    source   LowCardinality(String),
    reason   String,
    raw      String CODEC(ZSTD(3)),
    peer      String DEFAULT '',
    truncated Bool DEFAULT false
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ingested)
ORDER BY (ingested, agent_id)
TTL toDateTime(ingested) + INTERVAL ${SIEM_EVENTS_TTL_DAYS} DAY
SETTINGS ttl_only_drop_parts = 1;
-- Etap 6d: adres nadawcy syslog i przycięcie – do ponownego przetworzenia
-- kwarantanny (instalacje sprzed etapu 6: ponowne uruchomienie skryptu,
-- patrz README, „Kwarantanna”).
ALTER TABLE siem.quarantine ADD COLUMN IF NOT EXISTS peer String DEFAULT '';
ALTER TABLE siem.quarantine ADD COLUMN IF NOT EXISTS truncated Bool DEFAULT false;
-- Etap 7a (instalacje sprzed etapu 7: patrz README, „Tożsamości”).
ALTER TABLE siem.events ADD COLUMN IF NOT EXISTS user_identity LowCardinality(String) DEFAULT '' AFTER time_quality;

-- Konta: zapis (siem-writer) i odczyt (Grafana).
CREATE USER IF NOT EXISTS siem_writer IDENTIFIED WITH sha256_password BY '${SIEM_WRITER_PASSWORD}';
GRANT INSERT, SELECT ON siem.* TO siem_writer;

CREATE USER IF NOT EXISTS grafana IDENTIFIED WITH sha256_password BY '${SIEM_GRAFANA_PASSWORD}'
    SETTINGS readonly = 2;
GRANT SELECT ON siem.* TO grafana;

-- Panel Hliðskjálf (wyszukiwarka zdarzeń): tylko odczyt, z limitami czasu
-- (30 s), rozmiaru wyniku i pamięci (1 GB, maks. 2 GB) – zapytanie z panelu nie
-- może podnieść ich ponad MAX ani zagłodzić zapisu zdarzeń.
CREATE USER IF NOT EXISTS siem_panel IDENTIFIED WITH sha256_password BY '${SIEM_PANEL_PASSWORD}'
    SETTINGS readonly = 2, max_execution_time = 15 MAX 30, max_result_rows = 100000 MAX 100000,
             max_memory_usage = 1000000000 MAX 2000000000;
GRANT SELECT ON siem.* TO siem_panel;

-- Detektor (silnik zapytań, Gjallarhorn): tylko odczyt zdarzeń, z limitami –
-- reguła nie może zagłodzić zapisu ani wyszukiwania.
CREATE USER IF NOT EXISTS siem_detector IDENTIFIED WITH sha256_password BY '${SIEM_DETECTOR_PASSWORD}'
    SETTINGS readonly = 2, max_execution_time = 60 MAX 120, max_memory_usage = 1000000000 MAX 2000000000;
GRANT SELECT ON siem.events TO siem_detector;
SQL
