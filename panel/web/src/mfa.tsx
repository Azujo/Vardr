// Drugi składnik logowania (TOTP): konfiguracja aplikacji (kod QR) i kody
// zapasowe – wspólne dla strony logowania i „Bezpieczeństwa konta”.
import { useState } from "react";
import { Alert, Button, Checkbox, Code, CopyButton, Group, Image, List, SimpleGrid, Stack, Text, TextInput } from "@mantine/core";
import { IconCheck, IconCopy, IconDownload } from "@tabler/icons-react";
import type { MFASetup } from "./api";

export function MFASetupView({ setup }: { setup: MFASetup }) {
  return (
    <Stack gap="xs">
      <List size="sm" type="ordered" spacing={4}>
        <List.Item>
          Zainstaluj na telefonie aplikację uwierzytelniającą, np. Microsoft Authenticator, Google Authenticator albo Aegis.
        </List.Item>
        <List.Item>Dodaj konto, skanując kod QR (albo wpisz klucz ręcznie).</List.Item>
        <List.Item>Wpisz poniżej 6-cyfrowy kod, który pokaże aplikacja.</List.Item>
      </List>
      <Group justify="center">
        <Image src={setup.qr} alt="kod QR konfiguracji aplikacji uwierzytelniającej" w={200} h={200} fit="contain" bg="white" p={4} />
      </Group>
      <Text size="xs" c="dimmed" ta="center">
        Klucz do wpisania ręcznie ({setup.issuer}: {setup.account}):
      </Text>
      <Group justify="center" gap="xs">
        <Code fz="sm">{setup.secret}</Code>
        <CopyButton value={setup.secret.replace(/ /g, "")}>
          {({ copied, copy }) => (
            <Button size="compact-xs" variant="subtle" onClick={copy} leftSection={copied ? <IconCheck size={12} /> : <IconCopy size={12} />}>
              {copied ? "skopiowano" : "kopiuj"}
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
  return (
    <TextInput
      label={allowRecovery ? "Kod z aplikacji albo kod zapasowy" : "Kod z aplikacji"}
      placeholder={allowRecovery ? "123456 albo abcde-12345" : "123456"}
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
  const [saved, setSaved] = useState(false);
  const text = codes.join("\n");
  const download = () => {
    const blob = new Blob([`Vardr – kody zapasowe drugiego składnika logowania\nKażdy kod działa jeden raz.\n\n${text}\n`], {
      type: "text/plain",
    });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "vardr-kody-zapasowe.txt";
    a.click();
    URL.revokeObjectURL(a.href);
  };
  return (
    <Stack gap="sm">
      <Alert color="yellow" title="Zapisz kody zapasowe">
        Każdy kod pozwala zalogować się jeden raz bez telefonu (zgubiony, rozładowany). Przechowuj je bezpiecznie, np.
        w menedżerze haseł. <b>Nie zostaną pokazane ponownie.</b>
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
              {copied ? "Skopiowano" : "Kopiuj"}
            </Button>
          )}
        </CopyButton>
        <Button size="xs" variant="light" leftSection={<IconDownload size={14} />} onClick={download}>
          Pobierz .txt
        </Button>
      </Group>
      <Checkbox label="Zapisałem kody zapasowe" checked={saved} onChange={(e) => setSaved(e.currentTarget.checked)} />
      <Button disabled={!saved} onClick={onDone}>
        {doneLabel}
      </Button>
    </Stack>
  );
}
