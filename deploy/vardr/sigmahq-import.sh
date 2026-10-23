#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SigmaHQ rule import on an installed server (install.sh) – the equivalent of
# the procedure in docs/en/rules.md ("Importing SigmaHQ rules") without the
# Vardr repository.
#
#   sudo ./sigmahq-import.sh            download/update SigmaHQ rules
#   sudo ./sigmahq-import.sh --remove   remove SigmaHQ rules from the server
#
# Reguły dla zbieranych źródeł trafiają do rules/<wersja>/sigmahq, te
# z parserem Vardra niezgodne są pomijane, a wszystkie zaimportowane są
# WYŁĄCZONE – włącza się je w panelu (Reguły, filtr SigmaHQ, najlepiej przez
# tryb próbny). Włączenia z panelu zostają przy aktualizacji (zapisane po id
# reguły). Nowa wersja katalogu reguł jest przełączana atomowo, detektor
# wczytuje ją w ciągu 30 s. Aktualizacja Vardra (install.sh) przenosi
# zaimportowane reguły do nowej wersji.
#
# Reguły SigmaHQ: https://github.com/SigmaHQ/sigma, licencja Detection Rule
# License (DRL) 1.1 – autorzy reguł są widoczni w panelu przy regule i alercie.
set -euo pipefail
cd "$(dirname "$0")"
umask 022

[ "$(id -u)" = 0 ] || { echo "run as root (sudo $0)" >&2; exit 1; }
[ -L rules/current ] || { echo "no rules/current – run in the Vardr installation directory" >&2; exit 1; }
env_get() { sed -n "s/^$1=//p" .env | tail -1; }
owner="$(env_get VARDR_UID):$(env_get VARDR_GID)"

# Kategorie dla źródeł, które Vardr zbiera (agent Windows, Entra ID).
dirs="windows/process_creation windows/powershell/powershell_script windows/builtin/security windows/builtin/system
windows/builtin/windefend windows/network_connection windows/file/file_event windows/dns_query windows/registry/registry_set
cloud/azure/signin_logs cloud/azure/audit_logs"

bad=""
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# Nazwa nowej wersji – unikalna także przy dwóch uruchomieniach w tej samej sekundzie.
new="v$(date +%Y%m%d%H%M%S)"
while [ -e "rules/$new" ]; do sleep 1; new="v$(date +%Y%m%d%H%M%S)"; done
mkdir -p "$work/$new"
cp -a rules/current/. "$work/$new/"
rm -rf "$work/$new/sigmahq"

if [ "${1:-}" != --remove ]; then
  echo "== downloading SigmaHQ (github.com/SigmaHQ/sigma)"
  curl -fsSL https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master | tar -xz -C "$work"
  src="$work/sigma-master"
  for d in $dirs; do
    [ -d "$src/rules/$d" ] || continue
    mkdir -p "$work/$new/sigmahq/$d"
    cp -r "$src/rules/$d/." "$work/$new/sigmahq/$d/"
  done
  # Tylko reguły stabilne i testowe (bez experimental, deprecated, unsupported).
  grep -rlE '^status: (experimental|deprecated|unsupported)' "$work/$new/sigmahq" | xargs -r rm
  echo "== checking with the Vardr parser"
  bin/siem-detector check "$work/$new" > "$work/check.txt" 2>&1 || true
  bad=$(sed -nE 's/^BŁĄD +(sigmahq\/[^:]+\.ya?ml):.*/\1/p' "$work/check.txt" | sort -u)
  # shellcheck disable=SC2086
  [ -z "$bad" ] || (cd "$work/$new" && echo "$bad" | xargs -r rm -f)
  # Wszystkie wyłączone w plikach – inaczej włączyłyby się setki reguł naraz.
  find "$work/$new/sigmahq" -name '*.yml' -exec sh -c 'printf "\nvardr:\n  enabled: false\n" >> "$1"' _ {} \;
  cp "$src/LICENSE" "$work/$new/sigmahq/LICENSE.SigmaHQ.md" 2>/dev/null || true
  cat > "$work/$new/sigmahq/README.md" <<EOF
# SigmaHQ rules

Rules from https://github.com/SigmaHQ/sigma (imported $(date -I), sigmahq-import.sh),
license Detection Rule License (DRL) 1.1: https://github.com/SigmaHQ/Detection-Rule-License
Authors of each rule – the \`author\` field in the file (shown in the panel with the rule and alert).
EOF
fi

if ! bin/siem-detector check "$work/$new" > "$work/check.txt" 2>&1; then
  grep -m 20 -E '^(ERROR|BŁĄD)' "$work/check.txt" >&2 || true
  echo "ERROR: the new rule set does not pass the check – nothing was changed" >&2
  exit 1
fi

mv "$work/$new" "rules/$new"
chown -R "$owner" "rules/$new"
ln -sfn "$new" rules/current.tmp && mv -T rules/current.tmp rules/current
chown -h "$owner" rules/current
find rules -mindepth 1 -maxdepth 1 -type d -name 'v*' | sort | head -n -3 | xargs -r rm -rf

n=$(find "rules/$new/sigmahq" -name '*.yml' 2>/dev/null | wc -l || true)
if [ "${1:-}" = --remove ]; then
  echo "SigmaHQ rules removed (rules version $new)."
else
  echo "Imported $n SigmaHQ rules (disabled, rules version $new; incompatible skipped: $(echo "$bad" | grep -c . || true))."
  echo "The detector loads them within 30 s. Enabling: panel → Detection rules, SigmaHQ filter (preferably via trial mode)."
fi
