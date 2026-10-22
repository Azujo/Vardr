// SPDX-License-Identifier: AGPL-3.0-or-later

// Moje konto → Bezpieczeństwo: drugi składnik logowania (TOTP) – włączenie,
// nowe kody zapasowe, wyłączenie (gdy polityka panelu go nie wymaga).
import { useCallback, useEffect, useState } from "react";
import { Alert, Badge, Button, Card, Group, Modal, PasswordInput, Stack, Text, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconShieldCheck, IconShieldOff } from "@tabler/icons-react";
import { api, formatDate, type MFASetup, type MFAStatus } from "../api";
import { CodeInput, MFASetupView, RecoveryCodesView } from "../mfa";

const policyText: Record<string, string> = {
  all: "wymagany od wszystkich kont",
  admins: "wymagany od administratorów",
  none: "dobrowolny",
};

type Dialog =
  | { kind: "enable"; setup?: MFASetup }
  | { kind: "recovery" }
  | { kind: "disable" }
  | { kind: "codes"; codes: string[] };

export default function AccountSecurityPage() {
  const [st, setSt] = useState<MFAStatus | null>(null);
  const [error, setError] = useState("");
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api
      .mfaStatus()
      .then(setSt)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);
  useEffect(load, [load]);

  const open = (d: Dialog) => {
    setPassword("");
    setCode("");
    setDialog(d);
  };
  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  if (error) return <Alert color="red">{error}</Alert>;
  if (!st) return null;

  return (
    <Stack maw={720}>
      <div>
        <Title order={2}>Bezpieczeństwo konta</Title>
        <Text c="dimmed" size="sm">
          Drugi składnik logowania: po haśle panel prosi o kod z aplikacji uwierzytelniającej na telefonie. Kradzież samego
          hasła nie wystarczy wtedy do zalogowania.
        </Text>
      </div>
      {!st.available && (
        <Alert color="gray">Drugi składnik nie jest skonfigurowany na serwerze (brak klucza MFA) – zgłoś to administratorowi.</Alert>
      )}
      {st.available && (
        <Card withBorder>
          <Stack gap="xs">
            <Group justify="space-between">
              <Group gap="xs">
                {st.enabled ? <IconShieldCheck color="var(--mantine-color-green-6)" /> : <IconShieldOff color="var(--mantine-color-gray-6)" />}
                <Text fw={500}>Aplikacja uwierzytelniająca (TOTP)</Text>
              </Group>
              {st.enabled ? <Badge color="green">włączona</Badge> : <Badge color="gray">wyłączona</Badge>}
            </Group>
            <Text size="sm" c="dimmed">
              W tym panelu drugi składnik jest {policyText[st.policy]}
              {st.required ? " – także od Ciebie" : ""}.
              {st.enabled && ` Włączony ${formatDate(st.enabled_at)}, kody zapasowe: ${st.recovery_left ?? 0} z 10.`}
            </Text>
            {st.enabled && (st.recovery_left ?? 0) <= 2 && (
              <Alert color="orange">Zostało mało kodów zapasowych – wygeneruj nowe.</Alert>
            )}
            <Group gap="xs">
              {!st.enabled && <Button onClick={() => open({ kind: "enable" })}>Włącz</Button>}
              {st.enabled && (
                <Button variant="light" onClick={() => open({ kind: "recovery" })}>
                  Nowe kody zapasowe
                </Button>
              )}
              {st.enabled && !st.required && (
                <Button variant="light" color="red" onClick={() => open({ kind: "disable" })}>
                  Wyłącz
                </Button>
              )}
            </Group>
          </Stack>
        </Card>
      )}

      <Modal
        opened={!!dialog}
        onClose={() => {
          setDialog(null);
          load();
        }}
        title={
          dialog?.kind === "enable"
            ? "Włączenie drugiego składnika"
            : dialog?.kind === "recovery"
              ? "Nowe kody zapasowe"
              : dialog?.kind === "disable"
                ? "Wyłączenie drugiego składnika"
                : "Kody zapasowe"
        }
        centered
        size="md"
      >
        {dialog?.kind === "enable" && !dialog.setup && (
          <Stack>
            <PasswordInput label="Twoje hasło" value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoFocus />
            <Button
              loading={busy}
              disabled={!password}
              onClick={() => void run(async () => setDialog({ kind: "enable", setup: await api.mfaSetup(password) }))}
            >
              Dalej
            </Button>
          </Stack>
        )}
        {dialog?.kind === "enable" && dialog.setup && (
          <Stack>
            <MFASetupView setup={dialog.setup} />
            <CodeInput value={code} onChange={setCode} autoFocus={false} />
            <Button
              loading={busy}
              disabled={!code}
              onClick={() =>
                void run(async () => {
                  const r = await api.mfaConfirm(code);
                  setDialog({ kind: "codes", codes: r.recovery_codes });
                })
              }
            >
              Włącz
            </Button>
          </Stack>
        )}
        {(dialog?.kind === "recovery" || dialog?.kind === "disable") && (
          <Stack>
            {dialog.kind === "recovery" && (
              <Text size="sm">Dotychczasowe kody zapasowe przestaną działać.</Text>
            )}
            {dialog.kind === "disable" && (
              <Alert color="orange">Bez drugiego składnika do zalogowania wystarczy samo hasło.</Alert>
            )}
            <PasswordInput label="Twoje hasło" value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoFocus />
            <CodeInput value={code} onChange={setCode} allowRecovery autoFocus={false} />
            <Button
              color={dialog.kind === "disable" ? "red" : undefined}
              loading={busy}
              disabled={!password || !code}
              onClick={() =>
                void run(async () => {
                  if (dialog.kind === "recovery") {
                    const r = await api.mfaRecovery(password, code);
                    setDialog({ kind: "codes", codes: r.recovery_codes });
                  } else {
                    await api.mfaDisable(password, code);
                    notifications.show({ color: "green", message: "Drugi składnik wyłączony" });
                    setDialog(null);
                    load();
                  }
                })
              }
            >
              {dialog.kind === "recovery" ? "Wygeneruj" : "Wyłącz"}
            </Button>
          </Stack>
        )}
        {dialog?.kind === "codes" && (
          <RecoveryCodesView
            codes={dialog.codes}
            doneLabel="Gotowe"
            onDone={() => {
              setDialog(null);
              load();
            }}
          />
        )}
      </Modal>
    </Stack>
  );
}
