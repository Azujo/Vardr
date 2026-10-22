#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Paczka instalacyjna serwera Vardr: dist/vardr-<wersja>-linux-amd64.tar.gz
# (programy, pliki stosu, reguły, agent Windows, install.sh) + plik .sha256.
#
#   deploy/vardr/build-bundle.sh [wersja]     domyślnie: git describe
#
# Frontend panelu: budowany przez npm, gdy jest dostępny; inaczej używany
# jest gotowy panel/web/dist (na stacji bez Node: deploy/lab/deploy.sh web).
# Pliki konfiguracji usług (NATS, ClickHouse, Saga, Grafana, Prometheus)
# i skrypty kopii są wspólne ze stosem laboratorium (deploy/lab).
set -euo pipefail
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
command -v go >/dev/null || export PATH="/c/Program Files/Go/bin:$PATH"

version="${1:-$(git describe --tags --always --dirty)}"
name="vardr-$version-linux-amd64"
stage="dist/$name"
lab=deploy/lab

echo "== Vardr $version"
if command -v npm >/dev/null; then
  echo "== frontend panelu (npm)"
  (cd panel/web && npm ci --no-audit --no-fund >/dev/null && npm run build >/dev/null)
else
  [ -f panel/web/dist/index.html ] || { echo "brak panel/web/dist – zbuduj frontend (npm albo deploy/lab/deploy.sh web)" >&2; exit 1; }
  newer=$(find panel/web/src panel/web/index.html -newer panel/web/dist/index.html -type f | head -3)
  [ -z "$newer" ] || { echo "panel/web/dist jest starszy niż źródła ($newer…) – przebuduj frontend" >&2; exit 1; }
  echo "== frontend panelu: gotowy panel/web/dist"
fi

echo "== reguły detekcji (sprawdzenie)"
GOOS= GOARCH= go run ./server/cmd/siem-detector check rules >/dev/null || { echo "reguły z błędami" >&2; exit 1; }

rm -rf "$stage"
mkdir -p "$stage/stack/bin" "$stage/stack/agent-dist" "$stage/stack/export-tools" "$stage/rules"

echo "== programy serwera (linux/amd64)"
ldv="-s -w -X siem/internal/svc.Version=$version"
declare -A pkg=(
  [siem-ingest]=server/cmd/siem-ingest [siem-normalizer]=server/cmd/siem-normalizer
  [siem-writer]=server/cmd/siem-writer [siem-archiver]=server/cmd/siem-archiver
  [siem-detector]=server/cmd/siem-detector [siem-backup]=server/cmd/siem-backup [siem-api]=panel/cmd/siem-api
)
for b in "${!pkg[@]}"; do
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$ldv" -o "$stage/stack/bin/$b" "./${pkg[$b]}"
done
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$version" -o "$stage/stack/bin/siem-collector" ./agent/cmd/siem_collector
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$version" -o "$stage/stack/bin/siem-connector" ./agent/cmd/siem_connector
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$stage/stack/bin/siem-pki" ./tools/cmd/siem-pki

echo "== agent Windows i czytnik eksportu"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o "$stage/stack/agent-dist/vardr-agent.exe" ./agent/cmd/vardr-agent
sed -n 's/^const version = "\(.*\)"/\1/p' agent/cmd/vardr-agent/main.go > "$stage/stack/agent-dist/AGENT_VERSION"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$version" \
  -o "$stage/stack/export-tools/odczytaj.exe" ./tools/cmd/odczytaj

echo "== pliki stosu"
tar -C "$lab" -cf - Dockerfile backup/Dockerfile msi/Dockerfile msi/agent.wxs nats clickhouse saga grafana prometheus \
  backup.sh restore.sh enroll-service.sh | tar -C "$stage/stack" -xf -
cp deploy/vardr/docker-compose.yml deploy/vardr/.dockerignore "$stage/stack/"
# Bez biblioteki SigmaHQ: administrator importuje ją na serwerze
# (stack/sigmahq-import.sh, instrukcja w panelu: Reguły → Import reguł SigmaHQ).
tar -C rules --exclude=./sigmahq -cf - . | tar -C "$stage/rules" -xf -
cp deploy/vardr/sigmahq-import.sh "$stage/stack/"
cp deploy/vardr/install.sh LICENSE "$stage/"
echo "$version" > "$stage/VERSION"
cat > "$stage/README.txt" <<EOF
Vardr $version – serwer SIEM

Instalacja (Linux x86_64, systemd, Docker Engine z wtyczką compose v2):

  tar xzf $name.tar.gz
  cd $name
  sudo ./install.sh

Aktualizacja: to samo polecenie z nowszej paczki (konfiguracja, certyfikaty
i dane zostają). Opcje: sudo ./install.sh --help
Dokumentacja: docs/instalacja.md w repozytorium Vardra.
Licencja: GNU AGPL-3.0 lub późniejsza (plik LICENSE), kod: https://github.com/Azujo/Vardr
EOF

echo "== archiwum"
# Prawa ustawiane w archiwum (na NTFS chmod nie działa): programy i skrypty
# wykonywalne, reszta czytelna dla kontenerów (ClickHouse, Postgres, Grafana
# działają jako własni użytkownicy); właściciel root.
py=python3
command -v py >/dev/null && py="py -3"
$py - "$stage" "dist/$name.tar.gz" <<'PY'
import os, sys, tarfile
stage, out = sys.argv[1], sys.argv[2]
def fix(ti):
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    rel = ti.name.replace("\\", "/")
    exe = ti.isdir() or rel.endswith(".sh") or "/stack/bin/" in rel
    ti.mode = 0o755 if exe else 0o644
    return ti
with tarfile.open(out, "w:gz") as t:
    t.add(stage, arcname=os.path.basename(stage), filter=fix)
PY
(cd dist && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
rm -rf "$stage"
ls -l "dist/$name.tar.gz" | awk '{printf "gotowe: %s (%.0f MB)\n", $NF, $5/1048576}'
cat "dist/$name.tar.gz.sha256"
