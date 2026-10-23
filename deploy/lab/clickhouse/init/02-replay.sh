#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Tabela zdarzeń odtworzonych z archiwum NIS2 (Urd, replay). Osobna od
# siem.events: odtworzenie nie zmienia danych produkcyjnych (ReplacingMergeTree
# usuwa duplikaty tylko w obrębie partycji) i nie trafia do detekcji.
# Dane żyją SIEM_REPLAY_TTL_DAYS dni od odtworzenia (replayed_at).
#
# Obraz ClickHouse uruchamia skrypt przy pierwszym starcie. Istniejąca baza:
#   docker compose exec -T clickhouse bash /docker-entrypoint-initdb.d/02-replay.sh
# (bezpieczne do wielokrotnego uruchamiania).
set -euo pipefail
ttl=${SIEM_REPLAY_TTL_DAYS:-7}

clickhouse client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery <<SQL
CREATE TABLE IF NOT EXISTS siem.events_replay
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
    user_identity        LowCardinality(String) DEFAULT '',
    replay_id            UInt32,
    replayed_at          DateTime64(3, 'UTC') DEFAULT now64(3),

    INDEX idx_user    user_name TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_ip      source_ip TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_raw     raw       TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4,
    INDEX idx_message message   TYPE tokenbf_v1(8192, 3, 0) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(replayed_at)
PARTITION BY toYYYYMMDD(replayed_at)
ORDER BY (replay_id, event_dataset, host_name, timestamp, event_id)
TTL toDateTime(replayed_at) + INTERVAL ${ttl} DAY
SETTINGS ttl_only_drop_parts = 1;

ALTER TABLE siem.events_replay ADD COLUMN IF NOT EXISTS user_identity LowCardinality(String) DEFAULT '' AFTER time_quality;
ALTER TABLE siem.events_replay MODIFY TTL toDateTime(replayed_at) + INTERVAL ${ttl} DAY;
SQL
echo "table siem.events_replay ready (retention ${ttl} days from the replay)"
