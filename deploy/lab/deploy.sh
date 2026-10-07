#!/bin/bash
# Wdrożenie stosu laboratoryjnego ze stacji (Git Bash) na VM – jedna droga
# zamiast ręcznego kopiowania, więc VM nie rozjeżdża się z repozytorium.
#
#   deploy/lab/deploy.sh                 konfiguracja + wszystkie usługi
#   deploy/lab/deploy.sh archiver api    wybrane cele
#
# Cele:
#   config      pliki stosu z deploy/lab (compose, Prometheus, Grafana, init baz,
#               skrypty); bez certs/, .env, bin/, danych – te zostają na VM
#   web         frontend panelu (budowany w kontenerze Node na VM, wynik do
#               panel/web/dist – potem cel api)
#   ingest normalizer writer archiver api
#               program dla Linuksa z wersją z gita (svc.Version), obraz
#               i restart usługi
#   agent       siem_agent.exe do paczek instalacyjnych panelu (agent-dist/)
#
# Zmienne: SIEM_LAB_HOST (siem@192.168.88.98), SIEM_LAB_KEY (~/.ssh/siem_lab),
# SIEM_LAB_DIR (~/siem-lab na VM).
set -euo pipefail
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
command -v go >/dev/null || export PATH="/c/Program Files/Go/bin:$PATH"

host="${SIEM_LAB_HOST:-siem@192.168.88.98}"
key="${SIEM_LAB_KEY:-$HOME/.ssh/siem_lab}"
dir="${SIEM_LAB_DIR:-siem-lab}"
remote() { ssh -i "$key" -o BatchMode=yes "$host" "cd $dir && $*"; }
copy() { scp -q -i "$key" -o BatchMode=yes "$@"; }

version="$(git describe --tags --always --dirty)"
declare -A pkg=(
  [ingest]=server/cmd/siem-ingest [normalizer]=server/cmd/siem-normalizer
  [writer]=server/cmd/siem-writer [archiver]=server/cmd/siem-archiver [api]=panel/cmd/siem-api
)

targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=(config ingest normalizer writer archiver api)

services=()
for t in "${targets[@]}"; do
  case "$t" in
  config)
    echo "== konfiguracja stosu"
    tar -C deploy/lab --exclude=./bin --exclude=./certs --exclude=./archive --exclude=./metrics \
      --exclude=./agent-dist --exclude=./.env --exclude='*.log' --exclude=./deploy.sh -cf - . |
      ssh -i "$key" -o BatchMode=yes "$host" "mkdir -p $dir && tar -xf - -C $dir"
    remote "docker compose config -q" && echo "   docker-compose.yml poprawny"
    ;;
  web)
    echo "== frontend panelu (Node na VM)"
    tar -C panel/web --exclude=node_modules --exclude=dist -cf - . |
      ssh -i "$key" -o BatchMode=yes "$host" 'rm -rf ~/webbuild/src ~/webbuild/public && mkdir -p ~/webbuild && tar -xf - -C ~/webbuild'
    ssh -i "$key" -o BatchMode=yes "$host" 'cd ~/webbuild && docker run --rm -u 1000:1000 -e HOME=/tmp -v $PWD:/app -w /app node:24-alpine sh -c "npm ci --no-audit --no-fund >/dev/null 2>&1 || npm install --no-audit --no-fund >/dev/null; npm run build" >&2 && tar -cf - dist' |
      (rm -rf panel/web/dist/assets && tar -xf - -C panel/web)
    ;;
  agent)
    echo "== agent Windows -> agent-dist/"
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o deploy/lab/bin/siem_agent.exe ./agent/cmd/siem_agent
    remote "mkdir -p agent-dist"
    copy deploy/lab/bin/siem_agent.exe "$host:$dir/agent-dist/siem_agent.exe"
    ;;
  ingest | normalizer | writer | archiver | api)
    echo "== $t ($version)"
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X siem/internal/svc.Version=$version" -o "deploy/lab/bin/" "./${pkg[$t]}"
    copy "deploy/lab/bin/$(basename "${pkg[$t]}")" "$host:$dir/bin/"
    services+=("$t")
    # Kopie ścieżki odtwarzania z archiwum używają tych samych programów.
    case "$t" in normalizer | writer) services+=("$t-replay") ;; esac
    ;;
  *)
    echo "nieznany cel: $t" >&2
    exit 2
    ;;
  esac
done

if [ ${#services[@]} -gt 0 ]; then
  echo "== obrazy i restart: ${services[*]}"
  remote "docker compose build ${services[*]} >/dev/null && docker compose up -d ${services[*]} 2>&1 | grep -E 'Started|Recreated|Error' || true"
  sleep 5
  remote "docker compose ps --format '{{.Service}}\t{{.Status}}' ${services[*]}"
fi
echo "gotowe: wersja $version"
