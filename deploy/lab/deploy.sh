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
#   rules       reguły detekcji z rules/ (sprawdzane przed wysłaniem)
#   ingest normalizer writer archiver detector api
#               program dla Linuksa z wersją z gita (svc.Version), obraz
#               i restart usługi
#   agent       siem_agent.exe do paczek instalacyjnych panelu (agent-dist/)
#   collector   siem-collector (kolektor syslog, kontener na VM; rejestracja:
#               deploy/lab/collector-enroll.sh)
#   tools       odczytaj.exe – czytnik eksportu archiwum dołączany do paczek (export-tools/)
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
  [detector]=server/cmd/siem-detector
)

targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=(config rules ingest normalizer writer archiver detector api)

services=()
for t in "${targets[@]}"; do
  case "$t" in
  config)
    echo "== konfiguracja stosu"
    tar -C deploy/lab --exclude=./bin --exclude=./certs --exclude=./archive --exclude=./metrics \
      --exclude=./agent-dist --exclude=./export-tools --exclude=./.env --exclude='*.log' --exclude=./deploy.sh -cf - . |
      ssh -i "$key" -o BatchMode=yes "$host" "mkdir -p $dir && tar --overwrite -xf - -C $dir"
    # --overwrite zapisuje pliki w miejscu (ten sam i-węzeł): kontenery montujące
    # pojedynczy plik (prometheus.yml, nats.conf, siem.xml) widzą nową treść;
    # podmiana pliku zostawiłaby im starą wersję.
    remote "docker compose config -q" && echo "   docker-compose.yml poprawny"
    # Start stosu po restarcie VM (boot.sh) – wpis @reboot w crontabie użytkownika.
    remote "crontab -l 2>/dev/null | grep -q siem-lab/boot.sh || (crontab -l 2>/dev/null; echo '@reboot \$HOME/siem-lab/boot.sh') | crontab -" &&
      echo "   start po restarcie VM: crontab @reboot boot.sh"
    remote "docker compose ps -q prometheus | grep -q . && docker compose kill -s HUP prometheus >/dev/null" &&
      echo "   Prometheus przeładował konfigurację" || true
    remote "docker compose ps -q nats | grep -q . && docker compose kill -s HUP nats >/dev/null" &&
      echo "   NATS przeładował konfigurację (zmiana limitów JetStream wymaga: docker compose restart nats)" || true
    ;;
  rules)
    echo "== reguły detekcji (rules/ -> rules/ na VM; detektor przeładuje je w ciągu 30 s)"
    GOOS= go run ./server/cmd/siem-detector check rules >/dev/null || { echo "reguły z błędami – popraw przed wdrożeniem" >&2; exit 1; }
    # Każde wdrożenie to nowy katalog rules/v<czas>; dowiązanie rules/current
    # przełączane atomowo (detektor montuje rules/ i nigdy nie widzi połowy
    # zestawu ani pustego katalogu). Starsze wersje i dawny układ są usuwane.
    ver="v$(date +%Y%m%d%H%M%S)"
    tar -C rules -cf - . | ssh -i "$key" -o BatchMode=yes "$host" "set -e; cd $dir; mkdir -p rules/$ver; tar -xf - -C rules/$ver
      ln -sfn $ver rules/current.tmp && mv -T rules/current.tmp rules/current
      find rules -mindepth 1 -maxdepth 1 ! -name $ver ! -name current -exec rm -rf {} +"
    ;;
  web)
    echo "== frontend panelu (Node na VM)"
    tar -C panel/web --exclude=node_modules --exclude=dist -cf - . |
      ssh -i "$key" -o BatchMode=yes "$host" 'rm -rf ~/webbuild/src ~/webbuild/public && mkdir -p ~/webbuild && tar -xf - -C ~/webbuild'
    ssh -i "$key" -o BatchMode=yes "$host" 'cd ~/webbuild && docker run --rm -u 1000:1000 -e HOME=/tmp -v $PWD:/app -w /app node:24-alpine sh -c "npm ci --no-audit --no-fund >/dev/null 2>&1 || npm install --no-audit --no-fund >/dev/null; npm run build" >&2 && tar -cf - dist' |
      (rm -rf panel/web/dist/assets && tar -xf - -C panel/web)
    ;;
  tools)
    echo "== czytnik eksportu (odczytaj.exe) -> export-tools/ ($version)"
    mkdir -p deploy/lab/export-tools
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$version" \
      -o deploy/lab/export-tools/odczytaj.exe ./tools/cmd/odczytaj
    remote "mkdir -p export-tools"
    copy deploy/lab/export-tools/odczytaj.exe "$host:$dir/export-tools/odczytaj.exe"
    ;;
  agent)
    echo "== agent Windows -> agent-dist/ (program i instalator MSI)"
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o deploy/lab/bin/siem_agent.exe ./agent/cmd/siem_agent
    agent_version=$(sed -n 's/^const version = "\(.*\)"/\1/p' agent/cmd/siem_agent/main.go)
    remote "mkdir -p agent-dist msi"
    copy deploy/lab/bin/siem_agent.exe "$host:$dir/agent-dist/siem_agent.exe"
    copy deploy/lab/msi/Dockerfile deploy/lab/msi/agent.wxs "$host:$dir/msi/"
    # MSI z CA tej instalacji (certs/ca.crt na serwerze), narzędziem wixl w kontenerze.
    remote "docker image inspect siem/wixl:lab >/dev/null 2>&1 || docker build -q -t siem/wixl:lab msi >/dev/null; \
      docker run --rm -u 1000:1000 -v \$PWD/msi:/src:ro -v \$PWD/agent-dist:/out \
        -v \$PWD/agent-dist/siem_agent.exe:/w/siem_agent.exe:ro -v \$PWD/certs/ca.crt:/w/ca.crt:ro \
        siem/wixl:lab -a x64 -D Version=$agent_version -o /out/heimdall-agent.msi /src/agent.wxs 2>&1 | grep -v GLib-GObject-WARNING | grep -v '^\$' || true; \
      ls -l agent-dist/heimdall-agent.msi | awk '{print \"   MSI: \" \$5 \" B\"}'"
    ;;
  ingest | normalizer | writer | archiver | detector | api)
    echo "== $t ($version)"
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X siem/internal/svc.Version=$version" -o "deploy/lab/bin/" "./${pkg[$t]}"
    copy "deploy/lab/bin/$(basename "${pkg[$t]}")" "$host:$dir/bin/"
    services+=("$t")
    # Kopie ścieżki odtwarzania z archiwum używają tych samych programów.
    case "$t" in normalizer | writer) services+=("$t-replay") ;; esac
    ;;
  collector)
    echo "== collector ($version)"
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath       -ldflags="-s -w -X main.version=$version" -o deploy/lab/bin/siem-collector ./agent/cmd/siem_collector
    copy deploy/lab/bin/siem-collector "$host:$dir/bin/"
    # Bez rejestracji (collector/collector.yaml) kontener tylko by się restartował.
    if remote "test -f collector/collector.yaml"; then
      services+=("collector")
    else
      remote "docker compose build collector >/dev/null" && echo "   obraz gotowy – zarejestruj kolektor: deploy/lab/collector-enroll.sh"
    fi
    ;;
  connector)
    echo "== connector + entrasim ($version)"
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$version" -o deploy/lab/bin/siem-connector ./agent/cmd/siem_connector
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o deploy/lab/bin/siem-entrasim ./tools/cmd/entrasim
    copy deploy/lab/bin/siem-connector "$host:$dir/bin/"
    copy deploy/lab/bin/siem-entrasim "$host:$dir/bin/"
    # Bez rejestracji (connector/connector.yaml) kontenery tylko by się restartowały.
    if remote "test -f connector/connector.yaml"; then
      services+=("entrasim" "connector")
    else
      remote "docker compose build connector entrasim >/dev/null" && echo "   obrazy gotowe – zarejestruj konektor: deploy/lab/service-enroll.sh connector"
    fi
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
