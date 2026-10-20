#!/bin/bash
# Monitor potoku na czas testu obciążenia: co INTERVAL s jedna linia
# z metrykami Prometheusa (przepływ, odmowy, kolejki, opóźnienie, CPU usług
# i ClickHouse, wolne miejsce). Opis: docs/testy-obciazeniowe.md.
#
#   cd ~/siem-lab && nohup bash loadtest-monitor.sh 300 100 > ~/mon.log 2>&1 &
#
# Argumenty: odstęp w sekundach (60), liczba pomiarów (bez końca).
INTERVAL=${1:-60}
N=${2:-100000}
q() { curl -s --get "http://127.0.0.1:9090/api/v1/query" --data-urlencode "query=$1" |
  python3 -c 'import json,sys
r=json.load(sys.stdin)["data"]["result"]
print(" ".join("%s=%s"%(x["metric"].get(sys.argv[1],"") if len(sys.argv)>1 else "", round(float(x["value"][1]),2)) for x in r) or "-")' "$2"; }
for i in $(seq 1 "$N"); do
  echo "$(date -u +%H:%M:%S)" \
    "| ingest/s $(q 'sum(rate(siem_ingest_events_total[1m]))')" \
    "| norm/s $(q 'sum(rate(siem_normalizer_events_total[1m]))')" \
    "| writer/s $(q 'sum(rate(siem_writer_rows_total[1m]))')" \
    "| det/s $(q 'sum(rate(siem_detector_events_total[1m]))')" \
    "| 429/503 $(q 'sum(rate(siem_ingest_batches_total{result!="accepted"}[1m]))')" \
    "| pending $(q 'max by (consumer) (siem_queue_pending_messages)' consumer)" \
    "| fill $(q 'max(siem_queue_fill_ratio)')" \
    "| p99 lat $(q 'histogram_quantile(0.99, sum by (le) (rate(siem_writer_pipeline_latency_seconds_bucket[1m])))')s" \
    "| idxlag $(q 'max(siem_detector_index_lag_seconds)')s" \
    "| cpu $(q 'sum by (service) (rate(process_cpu_seconds_total{job="siem"}[1m]))' service)" \
    "| ch_cpu $(q 'sum(rate(ClickHouseProfileEvents_OSCPUVirtualTimeMicroseconds[1m])) / 1e6')" \
    "| load $(cut -d' ' -f1 /proc/loadavg)" \
    "| disk_root $(df --output=avail -BG / | tail -1 | tr -d ' ') arch $(df --output=avail -BG "$(sed -n 's/^SIEM_ARCHIVE_PATH=//p' .env 2>/dev/null || echo /)" 2>/dev/null | tail -1 | tr -d ' ')"
  [ "$i" -lt "$N" ] && sleep "$INTERVAL"
done
