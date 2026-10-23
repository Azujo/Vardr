// SPDX-License-Identifier: AGPL-3.0-or-later

// Instrukcja importu reguł SigmaHQ (to samo co docs/reguly.md, „Import
// reguł SigmaHQ”) – polecenia do skopiowania: na serwerze z instalacji
// (sigmahq-import.sh) albo w katalogu projektu (repozytorium Vardra).
import { ActionIcon, Alert, Anchor, Code, CopyButton, Group, List, SegmentedControl, Stack, Text, Tooltip } from "@mantine/core";
import { IconCheck, IconCopy } from "@tabler/icons-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

// Tytuły i uwagi kroków: rules: sigma.server.<i> / sigma.repo.<i> (title, note).
type Step = { ps: string; bash: string; note?: boolean };

// Serwer z instalacji (install.sh): jeden skrypt robi wszystkie kroki.
const serverSteps: { cmd: string; note?: boolean }[] = [
  { cmd: "sudo /opt/vardr/sigmahq-import.sh", note: true },
  { cmd: "sudo /opt/vardr/sigmahq-import.sh --remove" },
];

const steps: Step[] = [
  {
    ps: "git clone --depth 1 https://github.com/SigmaHQ/sigma.git ../sigma",
    bash: "git clone --depth 1 https://github.com/SigmaHQ/sigma.git ../sigma",
  },
  {
    ps: String.raw`$dirs = 'windows/process_creation','windows/powershell/powershell_script','windows/builtin/security','windows/builtin/system','windows/builtin/windefend','windows/network_connection','windows/file/file_event','windows/dns_query','windows/registry/registry_set','cloud/azure/signin_logs','cloud/azure/audit_logs'; foreach ($d in $dirs) { $src = "../sigma/rules/$d"; if (Test-Path $src) { New-Item -ItemType Directory -Force "rules/sigmahq/$d" | Out-Null; Copy-Item "$src/*" "rules/sigmahq/$d/" -Recurse -Force } }`,
    bash: String.raw`for d in windows/process_creation windows/powershell/powershell_script windows/builtin/security windows/builtin/system windows/builtin/windefend windows/network_connection windows/file/file_event windows/dns_query windows/registry/registry_set cloud/azure/signin_logs cloud/azure/audit_logs; do [ -d "../sigma/rules/$d" ] && mkdir -p "rules/sigmahq/$d" && cp -r "../sigma/rules/$d/." "rules/sigmahq/$d/"; done`,
    note: true,
  },
  {
    ps: String.raw`Get-ChildItem rules/sigmahq -Recurse -Filter *.yml | Where-Object { Select-String -Path $_.FullName -Pattern '^status: (experimental|deprecated|unsupported)' -Quiet } | Remove-Item`,
    bash: String.raw`grep -rlE '^status: (experimental|deprecated|unsupported)' rules/sigmahq | xargs -r rm`,
  },
  {
    ps: String.raw`& "C:\Program Files\Go\bin\go.exe" run ./server/cmd/siem-detector check rules > check.txt; "OK: " + (Select-String -Path check.txt -Pattern '^OK').Count; "błędy: " + (Select-String -Path check.txt -Pattern '^(?!OK|UWAGA)\S+\s+sigmahq/').Count`,
    bash: "go run ./server/cmd/siem-detector check rules > check.txt",
  },
  {
    ps: String.raw`Select-String -Path check.txt -Pattern '^(?!OK|UWAGA)\S+\s+(sigmahq/[^\s:]+\.yml)' | ForEach-Object { "rules/" + $_.Matches[0].Groups[1].Value } | Sort-Object -Unique | Where-Object { Test-Path $_ } | Remove-Item`,
    bash: String.raw`grep -vE '^(OK|UWAGA)' check.txt | sed -nE 's/^[^ ]+ +(sigmahq\/[^ :]+\.yml).*/rules\/\1/p' | sort -u | xargs -r rm`,
  },
  {
    ps: "Get-ChildItem rules/sigmahq -Recurse -Filter *.yml | ForEach-Object { [IO.File]::AppendAllText($_.FullName, \"`nvardr:`n  enabled: false`n\") }",
    bash: String.raw`find rules/sigmahq -name '*.yml' -exec sh -c 'printf "\nvardr:\n  enabled: false\n" >> "$1"' _ {} \;`,
    note: true,
  },
  {
    ps: String.raw`& "C:\Program Files\Git\bin\bash.exe" deploy/lab/deploy.sh rules`,
    bash: "deploy/lab/deploy.sh rules",
  },
];

function Cmd({ text }: { text: string }) {
  const { t } = useTranslation("rules");
  return (
    <Group wrap="nowrap" align="flex-start" gap={6}>
      <Code block fz="xs" style={{ flex: 1, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
        {text}
      </Code>
      <CopyButton value={text}>
        {({ copied, copy }) => (
          <Tooltip label={copied ? t("sigma.copied") : t("sigma.copy")}>
            <ActionIcon variant="light" onClick={copy} aria-label={t("sigma.copyCmd")}>
              {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
            </ActionIcon>
          </Tooltip>
        )}
      </CopyButton>
    </Group>
  );
}

export default function SigmaImportHelp() {
  const { t } = useTranslation("rules");
  const [shell, setShell] = useState<"server" | "ps" | "bash">("server");
  return (
    <Stack gap="sm">
      <Text size="sm">
        <Anchor href="https://github.com/SigmaHQ/sigma" target="_blank" rel="noopener noreferrer">
          SigmaHQ
        </Anchor>{" "}
        {t("sigma.intro")}
      </Text>
      <SegmentedControl
        value={shell}
        onChange={(v) => setShell(v as "server" | "ps" | "bash")}
        data={[
          { value: "server", label: t("sigma.server") },
          { value: "ps", label: t("sigma.ps") },
          { value: "bash", label: t("sigma.bash") },
        ]}
        w="fit-content"
      />
      {shell === "server" &&
        serverSteps.map((s, i) => (
          <Stack key={i} gap={4}>
            <Text size="sm" fw={600}>
              {i + 1}. {t(`sigma.serverSteps.${i}.title`)}
            </Text>
            <Cmd text={s.cmd} />
            {s.note && (
              <Text size="xs" c="dimmed">
                {t(`sigma.serverSteps.${i}.note`)}
              </Text>
            )}
          </Stack>
        ))}
      {shell !== "server" &&
        steps.map((s, i) => (
        <Stack key={i} gap={4}>
          <Text size="sm" fw={600}>
            {i + 1}. {t(`sigma.repoSteps.${i}.title`)}
          </Text>
          <Cmd text={shell === "ps" ? s.ps : s.bash} />
          {s.note && (
            <Text size="xs" c="dimmed">
              {t(`sigma.repoSteps.${i}.note`)}
            </Text>
          )}
        </Stack>
        ))}
      <Alert color="blue" variant="light" title={t("sigma.after")}>
        <List size="sm" spacing={2}>
          <List.Item>{t("sigma.after1")}</List.Item>
          <List.Item>{t("sigma.after2")}</List.Item>
          <List.Item>{t("sigma.after3")}</List.Item>
        </List>
      </Alert>
      <Text size="xs" c="dimmed">
        {t("sigma.license")}{" "}
        <Anchor href="https://github.com/SigmaHQ/Detection-Rule-License" target="_blank" rel="noopener noreferrer" size="xs">
          Detection Rule License (DRL) 1.1
        </Anchor>{" "}
        {t("sigma.licenseText")}
      </Text>
    </Stack>
  );
}
