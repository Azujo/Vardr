#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Vardr server installer (bundle vardr-<version>-linux-amd64.tar.gz).
#
#   sudo ./install.sh                         install (asks for the server address)
#   sudo ./install.sh --server siem.company.com,10.0.0.5 --yes
#                                             no questions (the first address goes
#                                             into the agent packages)
#   sudo ./install.sh                         on an existing installation: upgrade
#                                             (programs, stack files, rules; .env,
#                                             certificates and data stay)
#   sudo ./install.sh --uninstall [--purge]   remove the services; --purge also the data
#
# Options: --dir /opt/vardr (stack files), --data /srv/vardr (NIS2 archive,
# exports, backups – preferably a separate disk), --admin admin (first panel
# account).
#
# Requirements: Linux x86_64 with systemd, Docker Engine with the compose plugin (v2).
set -euo pipefail
umask 022

SRC="$(cd "$(dirname "$0")" && pwd)"
DIR=/opt/vardr
DATA=/srv/vardr
SERVER=""
ADMIN=admin
YES=0
ACTION=install
PURGE=0

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [ $# -gt 0 ]; do
  case "$1" in
  --dir) DIR="${2%/}"; shift 2 ;;
  --data) DATA="${2%/}"; shift 2 ;;
  --server) SERVER="$2"; shift 2 ;;
  --admin) ADMIN="$2"; shift 2 ;;
  --yes | -y) YES=1; shift ;;
  --uninstall) ACTION=uninstall; shift ;;
  --purge) PURGE=1; shift ;;
  -h | --help) usage ;;
  *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

say() { printf '\033[1m== %s\033[0m\n' "$*"; }
warn() { printf '\033[33mWARNING:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
ask() { # ask <pytanie> <domyślna> → odpowiedź
  local a
  if [ "$YES" = 1 ] || [ ! -t 0 ]; then echo "$2"; return; fi
  read -r -p "$1 [$2]: " a
  echo "${a:-$2}"
}
compose() { (cd "$DIR" && docker compose --progress quiet "$@"); }
env_get() { sed -n "s/^$1=//p" "$DIR/.env" 2>/dev/null | tail -1; }
secret() { openssl rand -hex "${1:-24}"; }

[ "$(id -u)" = 0 ] || die "run as root (sudo ./install.sh)"
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || die "Linux x86_64 required"
command -v systemctl >/dev/null || die "systemd required"

# ---- usunięcie ----
if [ "$ACTION" = uninstall ]; then
  [ -f "$DIR/docker-compose.yml" ] || die "no installation in $DIR"
  if [ "$PURGE" = 1 ]; then
    data_dirs=$(printf '%s ' "$(env_get SIEM_ARCHIVE_PATH)" "$(env_get SIEM_ARCHIVE_EXPORT_PATH)" "$(env_get SIEM_BACKUP_DIR)")
    echo "This will IRREVERSIBLY remove: services, databases (events, alerts, accounts), $DIR,"
    echo "the NIS2 archive, exports and backups: $data_dirs"
    read -r -p "Type DELETE to continue: " ok
    [ "$ok" = "DELETE" ] || [ "$ok" = "USUŃ" ] || die "aborted"
  fi
  say "stopping the services"
  systemctl disable --now vardr-restore.timer vardr.service 2>/dev/null || true
  if [ "$PURGE" = 1 ]; then
    compose --profile collector --profile connector down -v --remove-orphans || true
    # shellcheck disable=SC2086
    rm -rf "$DIR" $data_dirs /etc/vardr
    for d in $data_dirs; do rmdir "$(dirname "$d")" 2>/dev/null || true; done
  else
    compose --profile collector --profile connector down --remove-orphans || true
  fi
  rm -f /etc/systemd/system/vardr.service /etc/systemd/system/vardr-restore.service /etc/systemd/system/vardr-restore.timer
  systemctl daemon-reload
  if [ "$PURGE" = 1 ]; then
    echo "Vardr removed together with its data. The vardr system user remains (userdel vardr)."
  else
    echo "Services removed. The data remains: $DIR (configuration, certificates), Docker volumes vardr_*,"
    echo "the archive and backups. Installing from the bundle again will run Vardr on this data."
  fi
  exit 0
fi

# ---- sprawdzenie systemu ----
[ -d "$SRC/stack" ] && [ -f "$SRC/VERSION" ] || die "run install.sh from the extracted Vardr bundle"
VERSION=$(cat "$SRC/VERSION")
UPGRADE=0
[ -f "$DIR/.env" ] && UPGRADE=1

say "Vardr $VERSION – $([ $UPGRADE = 1 ] && echo "upgrading the installation in $DIR" || echo "new installation in $DIR")"

command -v docker >/dev/null || die "Docker is missing. Installation: https://docs.docker.com/engine/install/ (Debian/Ubuntu: packages docker-ce and docker-compose-plugin)"
docker info >/dev/null 2>&1 || die "Docker is not running (systemctl start docker)"
cv=$(docker compose version --short 2>/dev/null || true)
[ -n "$cv" ] || die "docker compose v2 plugin is missing (package docker-compose-plugin)"
[ "$(printf '%s\n2.20.0\n' "${cv#v}" | sort -V | head -1)" = 2.20.0 ] || die "docker compose $cv is too old – 2.20 or newer required"
getent group docker >/dev/null || die "no docker group"

missing=()
for c in openssl gpg flock curl ss; do command -v "$c" >/dev/null || missing+=("$c"); done
if [ ${#missing[@]} -gt 0 ]; then
  if command -v apt-get >/dev/null; then
    say "installing tools: ${missing[*]}"
    pkgs=()
    for c in "${missing[@]}"; do
      case "$c" in gpg) pkgs+=(gnupg) ;; flock) pkgs+=(util-linux) ;; ss) pkgs+=(iproute2) ;; *) pkgs+=("$c") ;; esac
    done
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}" >/dev/null
  else
    die "missing tools: ${missing[*]} – install them and run again"
  fi
fi

mem_gb=$(awk '/MemTotal/ {printf "%d", $2/1024/1024 + 0.5}' /proc/meminfo)
[ "$mem_gb" -ge 4 ] || die "not enough memory: ${mem_gb} GB (minimum 4 GB, 8 GB or more recommended)"
[ "$mem_gb" -ge 8 ] || warn "memory ${mem_gb} GB – works, but 8 GB or more is recommended"
docker_root=$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)
free_gb=$(df -BG --output=avail "$docker_root" | tail -1 | tr -dc 0-9)
[ "$free_gb" -ge 20 ] || die "not enough space in $docker_root: ${free_gb} GB (minimum 20 GB, 60 GB or more recommended)"
[ "$free_gb" -ge 60 ] || warn "free space in $docker_root: ${free_gb} GB – queues and the event database may need more (60 GB recommended)"

if [ $UPGRADE = 0 ]; then
  for p in 8443 8444 3000; do
    if ss -ltnH "sport = :$p" | grep -q .; then die "port $p is in use (ingest 8443, panel 8444, Grafana 3000)"; fi
  done
fi

# ---- parametry nowej instalacji ----
if [ $UPGRADE = 0 ]; then
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}' | head -1)
  fqdn=$(hostname -f 2>/dev/null || hostname)
  # Nazwa bez domeny (np. „server”) zwykle nie rozwiązuje się u agentów –
  # wtedy pierwszy (do paczek agentów) jest adres IP.
  if [[ $fqdn == *.* ]]; then def="$fqdn${ip:+,$ip}"; else def="${ip:+$ip,}$fqdn"; fi
  if [ -z "$SERVER" ] && [ "$YES" = 0 ] && [ -t 0 ]; then
    echo
    echo "Addresses agents and browsers use to connect to the server (DNS names and/or IPs,"
    echo "comma-separated). They go into the server certificate; the first one into the agent packages."
    SERVER=$(ask "Server addresses" "$def")
  fi
  SERVER="${SERVER:-$def}"
  SERVER=$(echo "$SERVER" | tr -d ' ')
  [ -n "$SERVER" ] || die "specify the server address (--server)"
  DATA=$(ask "Data directory (NIS2 archive, exports, backups)" "$DATA")
fi

# ---- użytkownik usług ----
if ! id vardr >/dev/null 2>&1; then
  say "vardr system user"
  useradd --system --user-group --home-dir "$DIR" --no-create-home --shell /usr/sbin/nologin vardr
fi
usermod -aG docker vardr
VUID=$(id -u vardr)
VGID=$(id -g vardr)

# ---- pliki stosu ----
say "stack files and programs ($DIR)"
mkdir -p "$DIR"
tar -C "$SRC/stack" -cf - . | tar -C "$DIR" --overwrite --no-same-owner -xf -
cp "$SRC/VERSION" "$DIR/VERSION"
mkdir -p "$DIR/rules" "$DIR/backup-state" "$DIR/metrics" "$DIR/certs"
# Reguły: każda wersja w osobnym katalogu, dowiązanie current przełączane
# atomowo (detektor nigdy nie widzi połowy zestawu); zostają 3 ostatnie.
rv="v$(date +%Y%m%d%H%M%S)"
while [ -e "$DIR/rules/$rv" ]; do sleep 1; rv="v$(date +%Y%m%d%H%M%S)"; done
mkdir -p "$DIR/rules/$rv"
tar -C "$SRC/rules" -cf - . | tar -C "$DIR/rules/$rv" --no-same-owner -xf -
# Reguły zaimportowane na serwerze (sigmahq-import.sh) przechodzą do nowej wersji.
[ -d "$DIR/rules/current/sigmahq" ] && cp -a "$DIR/rules/current/sigmahq" "$DIR/rules/$rv/"
ln -sfn "$rv" "$DIR/rules/current.tmp" && mv -T "$DIR/rules/current.tmp" "$DIR/rules/current"
find "$DIR/rules" -mindepth 1 -maxdepth 1 -type d -name 'v*' | sort | head -n -3 | xargs -r rm -rf

# ---- konfiguracja (.env) ----
if [ $UPGRADE = 0 ]; then
  say "konfiguracja i sekrety (.env)"
  mkdir -p /etc/vardr
  ram_ch=4g
  [ "$mem_gb" -lt 12 ] && ram_ch=3g
  [ "$mem_gb" -lt 8 ] && ram_ch=2g
  cat > "$DIR/.env" <<EOF
# Vardr – konfiguracja stosu (utworzona przez install.sh $VERSION, $(date -I)).
# Hasła są losowe; plik czyta tylko root i użytkownik vardr. Po zmianie:
#   cd $DIR && sudo docker compose up -d

# Adres serwera w paczkach agentów i adresy w certyfikacie serwera.
SIEM_PUBLIC_SERVER=${SERVER%%,*}
VARDR_SERVER_HOSTS=$SERVER,localhost,127.0.0.1

# Użytkownik usług stosu (właściciel plików).
VARDR_UID=$VUID
VARDR_GID=$VGID

CLICKHOUSE_ADMIN_USER=siem_admin
CLICKHOUSE_ADMIN_PASSWORD=$(secret)
CLICKHOUSE_WRITER_PASSWORD=$(secret)
CLICKHOUSE_GRAFANA_PASSWORD=$(secret)
CLICKHOUSE_PANEL_PASSWORD=$(secret)
CLICKHOUSE_DETECTOR_PASSWORD=$(secret)
SAGA_ADMIN_PASSWORD=$(secret)
SAGA_DB_PASSWORD=$(secret)
SAGA_ARCHIVER_PASSWORD=$(secret)
SAGA_DETECTOR_PASSWORD=$(secret)
GRAFANA_ADMIN_PASSWORD=$(secret 12)
SIEM_ALERT_RELAY_TOKEN=$(secret 32)

# Retencja zdarzeń w ClickHouse (dni) i surowego XML (dni, ≤ zdarzeń).
SIEM_EVENTS_TTL_DAYS=5
SIEM_RAW_TTL_DAYS=2
# Silniki detekcji: stream (w locie), index_query (zapytania) albo both.
SIEM_DETECTION_MODE=both
# Pamięć ClickHouse (dobrana do $mem_gb GB RAM).
VARDR_CLICKHOUSE_MEM=$ram_ch

# Archiwum NIS2 (Urd), eksporty dla audytora i kopie zapasowe – katalogi
# na hoście (najlepiej osobny dysk). Retencję archiwum ustawia się w panelu.
SIEM_ARCHIVE_PATH=$DATA/archive
SIEM_ARCHIVE_EXPORT_PATH=$DATA/export
SIEM_BACKUP_DIR=$DATA/backup
SIEM_ARCHIVE_RETENTION_DAYS=30
# Hasło szyfrujące kopie zapasowe (poza katalogiem stosu i poza kopiami).
VARDR_BACKUP_PASS_FILE=/etc/vardr/backup.pass

# Porty (zmiana portu ingest wymaga nowych paczek agentów).
#VARDR_INGEST_PORT=8443
#VARDR_PANEL_PORT=8444
#VARDR_GRAFANA_PORT=3000
EOF
fi
chmod 600 "$DIR/.env"

# Brakujące klucze w .env starszej instalacji (nowe ustawienia w nowej wersji).
ensure_env() { grep -q "^$1=" "$DIR/.env" || echo "$1=$2" >> "$DIR/.env"; }
ensure_env VARDR_UID "$VUID"
ensure_env VARDR_GID "$VGID"

for d in "$(env_get SIEM_ARCHIVE_PATH)" "$(env_get SIEM_ARCHIVE_EXPORT_PATH)" "$(env_get SIEM_BACKUP_DIR)"; do
  [ -n "$d" ] || continue
  mkdir -p "$d"
  chown "$VUID:$VGID" "$d"
  chmod 750 "$d"
done

# ---- certyfikaty ----
pki() { "$DIR/bin/siem-pki" "$@" -out "$DIR/certs"; }
if [ ! -f "$DIR/certs/ca.crt" ]; then
  say "certificate authority and server certificate"
  pki ca >/dev/null
  pki agents-ca >/dev/null
  pki server -hosts "$(env_get VARDR_SERVER_HOSTS)" >/dev/null
elif ! openssl x509 -checkend $((45 * 86400)) -noout -in "$DIR/certs/server.crt" >/dev/null 2>&1; then
  hosts=$(env_get VARDR_SERVER_HOSTS)
  if [ -n "$hosts" ]; then
    say "renewing the server certificate (expires within 45 days)"
    pki server -hosts "$hosts" >/dev/null
  else
    warn "the server certificate expires within 45 days – no VARDR_SERVER_HOSTS in .env, renew it manually (bin/siem-pki server)"
  fi
fi
[ -s "$DIR/certs/mfa.key" ] || openssl rand -hex 32 > "$DIR/certs/mfa.key"

# Hasło kopii zapasowych – przed startem (bez pliku Docker założyłby w jego
# miejscu katalog); pokazywane na końcu, bo trzeba je zapisać.
pass_banner=""
pass_file=$(env_get VARDR_BACKUP_PASS_FILE)
if [ -n "$pass_file" ] && [ ! -s "$pass_file" ]; then
  mkdir -p "$(dirname "$pass_file")"
  pass_banner=$("$DIR/backup.sh" password init)
  chown "$VUID:$VGID" "$pass_file"
  chmod 600 "$pass_file"
fi

chown -R "$VUID:$VGID" "$DIR"
chmod 750 "$DIR/certs" "$DIR/backup-state"
chmod 640 "$DIR"/certs/*.key "$DIR/certs/mfa.key"
chmod 755 "$DIR"

# ---- obrazy i paczka agenta ----
say "service images (the first run downloads the base images – a few minutes)"
compose build -q
say "agent MSI installer (with this server's certificate)"
agent_version=$(cat "$DIR/agent-dist/AGENT_VERSION")
docker build -q -t vardr/wixl:local "$DIR/msi" >/dev/null
docker run --rm -u "$VUID:$VGID" -v "$DIR/msi:/src:ro" -v "$DIR/agent-dist:/out" \
  -v "$DIR/agent-dist/vardr-agent.exe:/w/vardr-agent.exe:ro" -v "$DIR/certs/ca.crt:/w/ca.crt:ro" \
  vardr/wixl:local -a x64 -D Version="$agent_version" -o /out/vardr-agent.msi /src/agent.wxs 2>&1 |
  grep -v -e GLib-GObject-WARNING -e '^$' || true
[ -s "$DIR/agent-dist/vardr-agent.msi" ] || warn "the agent MSI installer was not built – packages from the panel will have no MSI"

# ---- usługi systemd ----
say "systemd services (stack start with the system, restores requested in the panel)"
docker_bin=$(command -v docker)
cat > /etc/systemd/system/vardr.service <<EOF
[Unit]
Description=Vardr SIEM (stos Docker Compose w $DIR)
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=vardr
Group=vardr
SupplementaryGroups=docker
WorkingDirectory=$DIR
ExecStart=$docker_bin compose up -d --remove-orphans
ExecStop=$docker_bin compose stop
TimeoutStartSec=900

[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/vardr-restore.service <<EOF
[Unit]
Description=Vardr – przywracanie z kopii zleconej w panelu
After=vardr.service

[Service]
Type=oneshot
User=vardr
Group=vardr
SupplementaryGroups=docker
WorkingDirectory=$DIR
ExecStart=$DIR/restore.sh --zlecenie
EOF
cat > /etc/systemd/system/vardr-restore.timer <<EOF
[Unit]
Description=Vardr – sprawdzanie zleceń przywracania co minutę

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable -q vardr.service vardr-restore.timer

# ---- start ----
say "starting the stack"
# compose up odtwarza tylko kontenery ze zmienionym obrazem lub konfiguracją;
# usługa systemd przejmuje stos (start z systemem, zatrzymanie przy wyłączeniu).
compose up -d --remove-orphans --quiet-pull || { compose ps; die "starting the stack failed – docker compose logs (in $DIR)"; }
systemctl start vardr.service
systemctl start vardr-restore.timer
port=$(env_get VARDR_PANEL_PORT)
port=${port:-8444}
printf 'waiting for the panel'
for i in $(seq 1 90); do
  curl -skf "https://127.0.0.1:$port/api/v1/health" >/dev/null 2>&1 && break
  [ "$i" = 90 ] && { echo; die "the panel does not respond – docker compose logs api (in $DIR)"; }
  printf .
  sleep 2
done
echo " ready"

admin_out=""
if [ $UPGRADE = 0 ]; then
  say "first panel account ($ADMIN)"
  # Bez linii logu programu (JSON) – tylko komunikat z kontem i hasłem.
  admin_out=$(compose run --rm --no-deps -T api bootstrap-admin -username "$ADMIN" 2>&1 | grep -v '^{') ||
    warn "the account was not created: $admin_out"
fi

# ---- podsumowanie ----
srv=$(env_get SIEM_PUBLIC_SERVER)
echo
say "Vardr $VERSION is running"
compose ps --format '  {{.Service}}\t{{.Status}}'
cat <<EOF

  Panel:     https://$srv:$port
  Grafana:   http://$srv:$(env_get VARDR_GRAFANA_PORT | grep . || echo 3000)  (admin, password: sudo grep GRAFANA_ADMIN_PASSWORD $DIR/.env)
  Agents:    $srv:$(env_get VARDR_INGEST_PORT | grep . || echo 8443)  (packages and enrollment tokens: panel → Agents)

  The panel certificate is issued by Vardr's local authority: import $DIR/certs/ca.crt
  into the trusted authorities of your browser (SHA-256 fingerprint below).
  $(openssl x509 -noout -fingerprint -sha256 -in "$DIR/certs/ca.crt" | cut -d= -f2)

  Firewall: open 8443/tcp (agents), 8444/tcp (panel), 3000/tcp (Grafana);
  syslog collector (sudo $DIR/enroll-service.sh collector): 514/udp and 514/tcp.
  SigmaHQ rules (optional, disabled until reviewed in the panel): sudo $DIR/sigmahq-import.sh
  Panel language: each account picks its own (account menu); notifications follow the
  system language (panel → Notifications).
  Commands: cd $DIR && sudo docker compose ps | logs <service>; sudo systemctl restart vardr
EOF
if [ -n "$admin_out" ]; then
  echo "$admin_out" | sed 's/^/  /'
fi
[ -n "$pass_banner" ] && echo "$pass_banner"
exit 0
