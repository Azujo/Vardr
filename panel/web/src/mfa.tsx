// SPDX-License-Identifier: AGPL-3.0-or-later

// Drugi składnik logowania (TOTP): konfiguracja aplikacji (kod QR) i kody
// zapasowe – wspólne dla strony logowania i „Bezpieczeństwa konta”.
import { useState } from "react";
import { Alert, Button, Checkbox, Code, CopyButton, Group, Image, List, SimpleGrid, Stack, Text, TextInput } from "@mantine/core";
import { IconCheck, IconCopy, IconDownload } from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import type { MFASetup } from "./api";

export function MFASetupView({ setup }: { setup: MFASetup }) {
  const { t } = useTranslation("account");
  return (
    <Stack gap="xs">
      <List size="sm" type="ordered" spacing={4}>
        <List.Item>{t("mfa.step1")}</List.Item>
        <List.Item>{t("mfa.step2")}</List.Item>
        <List.Item>{t("mfa.step3")}</List.Item>
      </List>
      <Group justify="center">
        <Image src={setup.qr} alt={t("mfa.qrAlt")} w={200} h={200} fit="contain" bg="white" p={4} />
      </Group>
      <Text size="xs" c="dimmed" ta="center">
        {t("mfa.manualKey", { issuer: setup.issuer, account: setup.account })}
      </Text>
      <Group justify="center" gap="xs">
        <Code fz="sm">{setup.secret}</Code>
        <CopyButton value={setup.secret.replace(/ /g, "")}>
          {({ copied, copy }) => (
            <Button size="compact-xs" variant="subtle" onClick={copy} leftSection={copied ? <IconCheck size={12} /> : <IconCopy size={12} />}>
              {copied ? t("mfa.copiedShort") : t("mfa.copyShort")}
            </Button>
          )}
        </CopyButton>
      </Group>
    </Stack>
  );
}

// Pole kodu: 6 cyfr z aplikacji albo (gdy allowRecovery) kod zapasowy.
export function CodeInput({
  value,
  onChange,
  allowRecovery = false,
  autoFocus = true,
}: {
  value: string;
  onChange: (v: string) => void;
  allowRecovery?: boolean;
  autoFocus?: boolean;
}) {
  const { t } = useTranslation("account");
  return (
    <TextInput
      label={allowRecovery ? t("mfa.codeOrRecovery") : t("mfa.code")}
      placeholder={allowRecovery ? t("mfa.codeOrRecoveryPlaceholder") : "123456"}
      autoComplete="one-time-code"
      inputMode={allowRecovery ? "text" : "numeric"}
      autoFocus={autoFocus}
      required
      maxLength={allowRecovery ? 16 : 7}
      value={value}
      onChange={(e) => onChange(e.currentTarget.value)}
      styles={{ input: { fontFamily: "monospace", letterSpacing: 2 } }}
    />
  );
}

// Kody zapasowe: pokazywane raz – do zapisania przed przejściem dalej.
export function RecoveryCodesView({ codes, doneLabel, onDone }: { codes: string[]; doneLabel: string; onDone: () => void }) {
  const { t } = useTranslation("account");
  const [saved, setSaved] = useState(false);
  const text = codes.join("\n");
  const download = () => {
    const blob = new Blob([`${t("mfa.fileHeader")}\n\n${text}\n`], {
      type: "text/plain",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = t("mfa.fileName");
    a.click();
    URL.revokeObjectURL(a.href);
  };
  return (
    <Stack gap="sm">
      <Alert color="yellow" title={t("mfa.saveTitle")}>
        {t("mfa.saveText")} <b>{t("mfa.saveOnce")}</b>
      </Alert>
      <SimpleGrid cols={2} spacing={4}>
        {codes.map((c) => (
          <Code key={c} fz="md" ta="center">
            {c}
          </Code>
        ))}
      </SimpleGrid>
      <Group gap="xs">
        <CopyButton value={text}>
          {({ copied, copy }) => (
            <Button size="xs" variant="light" onClick={copy} leftSection={copied ? <IconCheck size={14} /> : <IconCopy size={14} />}>
              {copied ? t("mfa.copied") : t("mfa.copy")}
            </Button>
          )}
        </CopyButton>
        <Button size="xs" variant="light" leftSection={<IconDownload size={14} />} onClick={download}>
          {t("mfa.download")}
        </Button>
      </Group>
      <Checkbox label={t("mfa.savedCheck")} checked={saved} onChange={(e) => setSaved(e.currentTarget.checked)} />
      <Button disabled={!saved} onClick={onDone}>
        {doneLabel}
      </Button>
    </Stack>
  );
}
