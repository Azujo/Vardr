// SPDX-License-Identifier: AGPL-3.0-or-later

// Instrukcja importu reguł SigmaHQ (to samo co docs/reguly.md, „Import
// reguł SigmaHQ”) – polecenia do skopiowania: na serwerze z instalacji
// (sigmahq-import.sh) albo w katalogu projektu (repozytorium Vardra).
import { ActionIcon, Alert, Anchor, Code, CopyButton, Group, List, SegmentedControl, Stack, Text, Tooltip } from "@mantine/core";
import { IconCheck, IconCopy } from "@tabler/icons-react";
import { useState } from "react";

type Step = { title: string; ps: string; bash: string; note?: string };

// Serwer z instalacji (install.sh): jeden skrypt robi wszystkie kroki.
const serverSteps: { title: string; cmd: string; note?: string }[] = [
  {
    title: "Import albo aktualizacja reguł (na serwerze Vardra)",
    cmd: "sudo /opt/vardr/sigmahq-import.sh",
    note: "Pobiera SigmaHQ z GitHuba, kopiuje reguły dla zbieranych źródeł, pomija niezgodne z parserem i wszystkie zostawia wyłączone. Aktualizacja Vardra zachowuje zaimportowane reguły.",
  },
  {
    title: "Usunięcie reguł SigmaHQ (opcjonalnie)",
    cmd: "sudo /opt/vardr/sigmahq-import.sh --remove",
  },
];

const steps: Step[] = [
  {
    title: "Pobranie repozytorium SigmaHQ obok projektu (aktualizacja: git -C ../sigma pull)",
    ps: "git clone --depth 1 https://github.com/SigmaHQ/sigma.git ../sigma",
    bash: "git clone --depth 1 https://github.com/SigmaHQ/sigma.git ../sigma",
  },
  {
    title: "Kopiowanie kategorii dla źródeł, które zbieramy",
    ps: String.raw`$dirs = 'windows/process_creation','windows/powershell/powershell_script','windows/builtin/security','windows/builtin/system','windows/builtin/windefend','windows/network_connection','windows/file/file_event','windows/dns_query','windows/registry/registry_set','cloud/azure/signin_logs','cloud/azure/audit_logs'; foreach ($d in $dirs) { $src = "../sigma/rules/$d"; if (Test-Path $src) { New-Item -ItemType Directory -Force "rules/sigmahq/$d" | Out-Null; Copy-Item "$src/*" "rules/sigmahq/$d/" -Recurse -Force } }`,
    bash: String.raw`for d in windows/process_creation windows/powershell/powershell_script windows/builtin/security windows/builtin/system windows/builtin/windefend windows/network_connection windows/file/file_event windows/dns_query windows/registry/registry_set cloud/azure/signin_logs cloud/azure/audit_logs; do [ -d "../sigma/rules/$d" ] && mkdir -p "rules/sigmahq/$d" && cp -r "../sigma/rules/$d/." "rules/sigmahq/$d/"; done`,
    note: "Przy aktualizacji najpierw usuń stary katalog rules/sigmahq – włączenia z panelu zostają (są zapisane po id reguły).",
  },
  {
    title: "Tylko reguły dojrzałe (stable i test)",
    ps: String.raw`Get-ChildItem rules/sigmahq -Recurse -Filter *.yml | Where-Object { Select-String -Path $_.FullName -Pattern '^status: (experimental|deprecated|unsupported)' -Quiet } | Remove-Item`,
    bash: String.raw`grep -rlE '^status: (experimental|deprecated|unsupported)' rules/sigmahq | xargs -r rm`,
  },
  {
    title: "Sprawdzenie parserem Vardra",
    ps: String.raw`& "C:\Program Files\Go\bin\go.exe" run ./server/cmd/siem-detector check rules > check.txt; "OK: " + (Select-String -Path check.txt -Pattern '^OK').Count; "błędy: " + (Select-String -Path check.txt -Pattern '^(?!OK|UWAGA)\S+\s+sigmahq/').Count`,
    bash: "go run ./server/cmd/siem-detector check rules > check.txt",
  },
  {
    title: "Usunięcie reguł, których Vardr nie obsługuje (potem krok 4 jeszcze raz – 0 błędów)",
    ps: String.raw`Select-String -Path check.txt -Pattern '^(?!OK|UWAGA)\S+\s+(sigmahq/[^\s:]+\.yml)' | ForEach-Object { "rules/" + $_.Matches[0].Groups[1].Value } | Sort-Object -Unique | Where-Object { Test-Path $_ } | Remove-Item`,
    bash: String.raw`grep -vE '^(OK|UWAGA)' check.txt | sed -nE 's/^[^ ]+ +(sigmahq\/[^ :]+\.yml).*/rules\/\1/p' | sort -u | xargs -r rm`,
  },
  {
    title: "Wszystkie zaimportowane reguły wyłączone w plikach",
    ps: "Get-ChildItem rules/sigmahq -Recurse -Filter *.yml | ForEach-Object { [IO.File]::AppendAllText($_.FullName, \"`nvardr:`n  enabled: false`n\") }",
    bash: String.raw`find rules/sigmahq -name '*.yml' -exec sh -c 'printf "\nvardr:\n  enabled: false\n" >> "$1"' _ {} \;`,
    note: "Bez tego po wdrożeniu włączyłyby się setki reguł naraz.",
  },
  {
    title: "Wdrożenie",
    ps: String.raw`& "C:\Program Files\Git\bin\bash.exe" deploy/lab/deploy.sh rules`,
    bash: "deploy/lab/deploy.sh rules",
  },
];

function Cmd({ text }: { text: string }) {
  return (
    <Group wrap="nowrap" align="flex-start" gap={6}>
      <Code block fz="xs" style={{ flex: 1, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
        {text}
      </Code>
      <CopyButton value={text}>
        {({ copied, copy }) => (
          <Tooltip label={copied ? "skopiowano" : "kopiuj"}>
            <ActionIcon variant="light" onClick={copy} aria-label="kopiuj polecenie">
              {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
            </ActionIcon>
          </Tooltip>
        )}
      </CopyButton>
    </Group>
  );
}

export default function SigmaImportHelp() {
  const [shell, setShell] = useState<"server" | "ps" | "bash">("server");
  return (
    <Stack gap="sm">
      <Text size="sm">
        <Anchor href="https://github.com/SigmaHQ/sigma" target="_blank" rel="noopener noreferrer">
          SigmaHQ
        </Anchor>{" "}
        to otwarta baza reguł Sigma. Vardr obsługuje podzbiór Sigmy – import kopiuje reguły dla zbieranych źródeł do{" "}
        <Code>rules/sigmahq/</Code>, odrzuca te, których parser nie obsługuje, i wdraża resztę <b>wyłączoną</b>. Na serwerze
        z instalatora wystarczy jeden skrypt; z repozytorium Vardra – polecenia w katalogu projektu. Opis:{" "}
        <Code>docs/reguly.md</Code>, „Import reguł SigmaHQ”.
      </Text>
      <SegmentedControl
        value={shell}
        onChange={(v) => setShell(v as "server" | "ps" | "bash")}
        data={[
          { value: "server", label: "Serwer (instalator)" },
          { value: "ps", label: "Repozytorium – PowerShell" },
          { value: "bash", label: "Repozytorium – Git Bash" },
        ]}
        w="fit-content"
      />
      {shell === "server" &&
        serverSteps.map((s, i) => (
          <Stack key={i} gap={4}>
            <Text size="sm" fw={600}>
              {i + 1}. {s.title}
            </Text>
            <Cmd text={s.cmd} />
            {s.note && (
              <Text size="xs" c="dimmed">
                {s.note}
              </Text>
            )}
          </Stack>
        ))}
      {shell !== "server" &&
        steps.map((s, i) => (
        <Stack key={i} gap={4}>
          <Text size="sm" fw={600}>
            {i + 1}. {s.title}
          </Text>
          <Cmd text={shell === "ps" ? s.ps : s.bash} />
          {s.note && (
            <Text size="xs" c="dimmed">
              {s.note}
            </Text>
          )}
        </Stack>
        ))}
      <Alert color="blue" variant="light" title="Po wdrożeniu">
        <List size="sm" spacing={2}>
          <List.Item>Reguły z SigmaHQ są na liście wyłączone (plik sigmahq/…) i nie obciążają detekcji.</List.Item>
          <List.Item>
            Wybraną regułę sprawdź zakładką <b>Test</b> na zdarzeniach z 7 dni; bez fałszywych alarmów – włącz przełącznikiem.
            Włączenie przetrwa ponowny import.
          </List.Item>
          <List.Item>Reguła na zdarzenia, których agent nie zbiera, wczyta się, ale test pokaże 0 zdarzeń.</List.Item>
        </List>
      </Alert>
      <Text size="xs" c="dimmed">
        Licencja reguł SigmaHQ:{" "}
        <Anchor href="https://github.com/SigmaHQ/Detection-Rule-License" target="_blank" rel="noopener noreferrer" size="xs">
          Detection Rule License (DRL) 1.1
        </Anchor>{" "}
        – użycie, zmiany i dystrybucja dozwolone, pod warunkiem zachowania autora (pole author), źródła i licencji. Nie usuwaj
        z reguł pól author i references.
      </Text>
    </Stack>
  );
}
