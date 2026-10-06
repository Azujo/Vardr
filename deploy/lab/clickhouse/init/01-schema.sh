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
    raw                  String CODEC(ZSTD(3)),
    truncated            Bool,
    parser_version       LowCardinality(String),
    time_quality         LowCardinality(String),

    INDEX idx_user    user_name TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_ip      source_ip TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_raw     raw       TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    INDEX idx_message message   TYPE tokenbf_v1(8192, 3, 0) GRANULARITY 4
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
    raw      String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ingested)
ORDER BY (ingested, agent_id)
TTL toDateTime(ingested) + INTERVAL ${SIEM_EVENTS_TTL_DAYS} DAY
SETTINGS ttl_only_drop_parts = 1;

-- Konta: zapis (siem-writer) i odczyt (Grafana).
CREATE USER IF NOT EXISTS siem_writer IDENTIFIED WITH sha256_password BY '${SIEM_WRITER_PASSWORD}';
GRANT INSERT, SELECT ON siem.* TO siem_writer;

CREATE USER IF NOT EXISTS grafana IDENTIFIED WITH sha256_password BY '${SIEM_GRAFANA_PASSWORD}'
    SETTINGS readonly = 2;
GRANT SELECT ON siem.* TO grafana;
SQL
