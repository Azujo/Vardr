#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Częste pola z mapy fields w osobnych kolumnach (internal/detect/columns.go):
# filtr po kolumnie nie czyta całej mapy. ClickHouse liczy je przy zapisie;
# starsze części – przy odczycie, z mapy. Bez przepisywania danych.
#
# Obraz ClickHouse uruchamia skrypt przy pierwszym starcie. Aktualizacja:
# install.sh przed startem detekcji (bezpieczne do wielokrotnego uruchamiania).
# Definicje kolumn sprawdza test TestColumnsScript.
set -euo pipefail

for table in siem.events siem.events_replay; do
clickhouse client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery <<SQL
ALTER TABLE $table
    ADD COLUMN IF NOT EXISTS f_commandline String MATERIALIZED multiIf(mapContains(fields, 'CommandLine'), fields['CommandLine'], fields[arrayFirst(k -> lowerUTF8(k) = 'commandline', mapKeys(fields))]) CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS f_image String MATERIALIZED multiIf(mapContains(fields, 'Image'), fields['Image'], mapContains(fields, 'NewProcessName'), fields['NewProcessName'], fields[arrayFirst(k -> lowerUTF8(k) = 'image', mapKeys(fields))]) CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS f_parentimage String MATERIALIZED multiIf(mapContains(fields, 'ParentImage'), fields['ParentImage'], mapContains(fields, 'ParentProcessName'), fields['ParentProcessName'], fields[arrayFirst(k -> lowerUTF8(k) = 'parentimage', mapKeys(fields))]) CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS f_targetfilename String MATERIALIZED multiIf(mapContains(fields, 'TargetFilename'), fields['TargetFilename'], fields[arrayFirst(k -> lowerUTF8(k) = 'targetfilename', mapKeys(fields))]) CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS f_targetobject String MATERIALIZED multiIf(mapContains(fields, 'TargetObject'), fields['TargetObject'], mapContains(fields, 'ObjectName'), fields['ObjectName'], fields[arrayFirst(k -> lowerUTF8(k) = 'targetobject', mapKeys(fields))]) CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS f_scriptblocktext String MATERIALIZED multiIf(mapContains(fields, 'ScriptBlockText'), fields['ScriptBlockText'], fields[arrayFirst(k -> lowerUTF8(k) = 'scriptblocktext', mapKeys(fields))]) CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS f_details String MATERIALIZED multiIf(mapContains(fields, 'Details'), fields['Details'], fields[arrayFirst(k -> lowerUTF8(k) = 'details', mapKeys(fields))]) CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS f_parentcommandline String MATERIALIZED multiIf(mapContains(fields, 'ParentCommandLine'), fields['ParentCommandLine'], fields[arrayFirst(k -> lowerUTF8(k) = 'parentcommandline', mapKeys(fields))]) CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS f_processname String MATERIALIZED multiIf(mapContains(fields, 'ProcessName'), fields['ProcessName'], fields[arrayFirst(k -> lowerUTF8(k) = 'processname', mapKeys(fields))]) CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS f_targetusername String MATERIALIZED multiIf(mapContains(fields, 'TargetUserName'), fields['TargetUserName'], fields[arrayFirst(k -> lowerUTF8(k) = 'targetusername', mapKeys(fields))]) CODEC(ZSTD(3)),
    ADD COLUMN IF NOT EXISTS f_present UInt16 MATERIALIZED toUInt16((mapContains(fields, 'CommandLine') OR arrayExists(k -> lowerUTF8(k) = 'commandline', mapKeys(fields)))) * 1 + toUInt16((mapContains(fields, 'Image') OR mapContains(fields, 'NewProcessName') OR arrayExists(k -> lowerUTF8(k) = 'image', mapKeys(fields)))) * 2 + toUInt16((mapContains(fields, 'ParentImage') OR mapContains(fields, 'ParentProcessName') OR arrayExists(k -> lowerUTF8(k) = 'parentimage', mapKeys(fields)))) * 4 + toUInt16((mapContains(fields, 'TargetFilename') OR arrayExists(k -> lowerUTF8(k) = 'targetfilename', mapKeys(fields)))) * 8 + toUInt16((mapContains(fields, 'TargetObject') OR mapContains(fields, 'ObjectName') OR arrayExists(k -> lowerUTF8(k) = 'targetobject', mapKeys(fields)))) * 16 + toUInt16((mapContains(fields, 'ScriptBlockText') OR arrayExists(k -> lowerUTF8(k) = 'scriptblocktext', mapKeys(fields)))) * 32 + toUInt16((mapContains(fields, 'Details') OR arrayExists(k -> lowerUTF8(k) = 'details', mapKeys(fields)))) * 64 + toUInt16((mapContains(fields, 'ParentCommandLine') OR arrayExists(k -> lowerUTF8(k) = 'parentcommandline', mapKeys(fields)))) * 128 + toUInt16((mapContains(fields, 'ProcessName') OR arrayExists(k -> lowerUTF8(k) = 'processname', mapKeys(fields)))) * 256 + toUInt16((mapContains(fields, 'TargetUserName') OR arrayExists(k -> lowerUTF8(k) = 'targetusername', mapKeys(fields)))) * 512;
SQL
done
