#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Start stosu po uruchomieniu VM (crontab użytkownika siem: @reboot).
# Sama polityka restart: unless-stopped nie wystarcza: po wyłączeniu VM
# przyciskiem w Proxmoxie (12.10.2026) Docker nie podniósł NATS ani
# Prometheusa, a reszta potoku przez 6 h restartowała się bez kolejki.
# compose up -d jest bezpieczne, gdy wszystko już działa (nic nie zmienia).
cd "$(dirname "$0")" || exit 1
sleep 30 # Docker i sieć
for i in 1 2 3; do
  docker compose up -d >>boot.log 2>&1 && break
  sleep 30
done
echo "$(date -Is) start stosu: $(docker compose ps --format '{{.Service}}' --status running | wc -l) usług działa" >>boot.log
