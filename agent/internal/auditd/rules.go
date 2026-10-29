// SPDX-License-Identifier: AGPL-3.0-or-later

package auditd

// Rules: zalecane reguły audytu dla reguł detekcji Vardra (klucze vardr_*).
// Instalacja: vardr-agent audit-rules | sudo tee /etc/audit/rules.d/50-vardr.rules
// && sudo augenrules --load. Obserwowane pliki nie muszą istnieć (wystarczy
// katalog nadrzędny). Uruchomienia programów – tylko przez zalogowanych
// użytkowników (auid ≥ 1000), bez procesów systemowych i nieudanych prób.
const Rules = `## Vardr – zalecane reguły audytu (vardr-agent audit-rules)
## Instalacja:
##   vardr-agent audit-rules | sudo tee /etc/audit/rules.d/50-vardr.rules
##   sudo augenrules --load
## Klucze (-k vardr_*) wykorzystują reguły detekcji Vardra (rules/linux).

## Konta i uprawnienia
-w /etc/passwd -p wa -k vardr_identity
-w /etc/shadow -p wa -k vardr_identity
-w /etc/group -p wa -k vardr_identity
-w /etc/gshadow -p wa -k vardr_identity
-w /etc/sudoers -p wa -k vardr_sudoers
-w /etc/sudoers.d -p wa -k vardr_sudoers

## SSH: klucze roota i konfiguracja serwera
-w /root/.ssh -p wa -k vardr_ssh_keys
-w /etc/ssh/sshd_config -p wa -k vardr_sshd

## Trwałość: cron, jednostki systemd, ld.so.preload
-w /etc/crontab -p wa -k vardr_cron
-w /etc/cron.d -p wa -k vardr_cron
-w /var/spool/cron -p wa -k vardr_cron
-w /etc/systemd/system -p wa -k vardr_systemd
-w /etc/ld.so.preload -p wa -k vardr_preload

## Konfiguracja audytu
-w /etc/audit -p wa -k vardr_audit_config

## Moduły jądra
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k vardr_modules

## Programy uruchamiane przez zalogowanych użytkowników (także przez sudo);
## bez nieudanych prób (powłoka i env szukają programu po katalogach PATH)
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -F success=1 -k vardr_exec
`
