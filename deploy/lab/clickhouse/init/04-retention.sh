#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Retencja zdarzeń w ClickHouse, także osobna dla wybranych zbiorów
# (event.dataset) – np. zapora krócej, logowania dłużej:
#
#   SIEM_EVENTS_TTL_DAYS=30                                  domyślnie
#   SIEM_EVENTS_TTL_DATASETS=fortigate.=7,windows.security=90  prefiks=dni
#
# Prefiks pasuje do początku nazwy zbioru (fortigate. → fortigate.traffic,
# fortigate.event…); przy kilku pasujących wygrywa najdłuższy. Zbiór bez
# reguły – SIEM_EVENTS_TTL_DAYS. Kwarantanna – zawsze SIEM_EVENTS_TTL_DAYS.
#
# Obraz ClickHouse uruchamia skrypt przy pierwszym starcie (po 01-schema.sh),
# instalator – przy każdej aktualizacji, ręcznie: clickhouse/retention.sh.
# Bez zmiany ustawień nic nie robi (skrót reguł w komentarzu tabeli). Nowe
# reguły obowiązują od razu dla nowych danych, a dla starszych części – przy
# ich scalaniu (materialize_ttl_after_modify = 0: bez przepisywania całej
# tabeli). Natychmiast, kosztem pełnego przepisania danych:
#   ALTER TABLE siem.events MATERIALIZE TTL
set -euo pipefail
days=${SIEM_EVENTS_TTL_DAYS:-5}
rules=${SIEM_EVENTS_TTL_DATASETS:-}
ch() { clickhouse client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --materialize_ttl_after_modify=0 "$@"; }

if ! [[ $days =~ ^[0-9]+$ ]] || (( days < 1 )); then
  echo "SIEM_EVENTS_TTL_DAYS must be a number of days ≥ 1" >&2; exit 2
fi

# Reguły posortowane od najdłuższego prefiksu: warunek reguły wyklucza
# dłuższe prefiksy, więc każdy zbiór ma dokładnie jedną retencję.
declare -a prefixes=() ttls=()
IFS=',' read -ra items <<<"$rules"
for item in "${items[@]}"; do
  item=${item// /}
  [ -z "$item" ] && continue
  if ! [[ $item =~ ^([a-z0-9_.-]+)=([0-9]+)$ ]] || (( BASH_REMATCH[2] < 1 )); then
    echo "SIEM_EVENTS_TTL_DATASETS: invalid rule \"$item\" (expected prefix=days, e.g. fortigate.=7)" >&2; exit 2
  fi
  prefixes+=("${BASH_REMATCH[1]}"); ttls+=("${BASH_REMATCH[2]}")
done
order=$(for i in "${!prefixes[@]}"; do printf '%d %d\n' "${#prefixes[$i]}" "$i"; done | sort -rn | cut -d' ' -f2)

base="toDateTime(ingested) + INTERVAL"
clauses=() taken=()
for i in $order; do
  p=${prefixes[$i]}
  cond="startsWith(event_dataset, '$p')"
  for q in "${taken[@]}"; do
    # Dłuższy prefiks zaczynający się od tego – ma własną regułę.
    [[ $q == "$p"* ]] && cond+=" AND NOT startsWith(event_dataset, '$q')"
  done
  clauses+=("$base ${ttls[$i]} DAY DELETE WHERE $cond")
  taken+=("$p")
done
if (( ${#taken[@]} == 0 )); then
  ttl="$base $days DAY"
else
  other=""
  for q in "${taken[@]}"; do other+="${other:+ OR }startsWith(event_dataset, '$q')"; done
  clauses+=("$base $days DAY DELETE WHERE NOT ($other)")
  ttl=$(IFS=','; echo "${clauses[*]}")
  ttl=${ttl//,toDateTime/, toDateTime}
fi

mark="vardr-ttl:$(printf '%s' "$ttl" | sha256sum | cut -c1-16)"
current=$(ch -q "SELECT comment FROM system.tables WHERE database = 'siem' AND name = 'events'")
if [ "$current" = "$mark" ]; then
  exit 0
fi
ch --multiquery <<SQL
ALTER TABLE siem.events MODIFY TTL $ttl;
ALTER TABLE siem.quarantine MODIFY TTL toDateTime(ingested) + INTERVAL $days DAY;
ALTER TABLE siem.events MODIFY COMMENT '$mark';
SQL
echo "Event retention: $days days${rules:+, per dataset: $rules}."
