// SPDX-License-Identifier: AGPL-3.0-or-later

// Moje konto → Bezpieczeństwo: drugi składnik logowania (TOTP) – włączenie,
// nowe kody zapasowe, wyłączenie (gdy polityka panelu go nie wymaga).
import { useCallback, useEffect, useState } from "react";
import { Alert, Badge, Button, Card, Group, Modal, PasswordInput, Stack, Text, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconShieldCheck, IconShieldOff } from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import { api, formatDate, type MFASetup, type MFAStatus } from "../api";
import { CodeInput, MFASetupView, RecoveryCodesView } from "../mfa";

type Dialog =
  | { kind: "enable"; setup?: MFASetup }
  | { kind: "recovery" }
  | { kind: "disable" }
  | { kind: "codes"; codes: string[] };

export default function AccountSecurityPage() {
  const { t } = useTranslation("account");
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
        <Title order={2}>{t("security.title")}</Title>
        <Text c="dimmed" size="sm">
          {t("security.intro")}
        </Text>
      </div>
      {!st.available && (
        <Alert color="gray">{t("security.unavailable")}</Alert>
      )}
      {st.available && (
        <Card withBorder>
          <Stack gap="xs">
            <Group justify="space-between">
              <Group gap="xs">
                {st.enabled ? <IconShieldCheck color="var(--mantine-color-green-6)" /> : <IconShieldOff color="var(--mantine-color-gray-6)" />}
                <Text fw={500}>{t("security.app")}</Text>
              </Group>
              {st.enabled ? <Badge color="green">{t("security.on")}</Badge> : <Badge color="gray">{t("security.off")}</Badge>}
            </Group>
            <Text size="sm" c="dimmed">
              {t(`security.policy.${st.policy}`)}
              {st.required ? t("security.requiredForYou") : "."}
              {st.enabled && ` ${t("security.enabledAt", { date: formatDate(st.enabled_at), left: st.recovery_left ?? 0 })}`}
            </Text>
            {st.enabled && (st.recovery_left ?? 0) <= 2 && (
              <Alert color="orange">{t("security.fewCodes")}</Alert>
            )}
            <Group gap="xs">
              {!st.enabled && <Button onClick={() => open({ kind: "enable" })}>{t("security.enable")}</Button>}
              {st.enabled && (
                <Button variant="light" onClick={() => open({ kind: "recovery" })}>
                  {t("security.newCodes")}
                </Button>
              )}
              {st.enabled && !st.required && (
                <Button variant="light" color="red" onClick={() => open({ kind: "disable" })}>
                  {t("security.disable")}
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
            ? t("security.enableTitle")
            : dialog?.kind === "recovery"
              ? t("security.newCodes")
              : dialog?.kind === "disable"
                ? t("security.disableTitle")
                : t("security.codesTitle")
        }
        centered
        size="md"
      >
        {dialog?.kind === "enable" && !dialog.setup && (
          <Stack>
            <PasswordInput label={t("security.yourPassword")} value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoFocus />
            <Button
              loading={busy}
              disabled={!password}
              onClick={() => void run(async () => setDialog({ kind: "enable", setup: await api.mfaSetup(password) }))}
            >
              {t("security.next")}
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
              {t("security.enable")}
            </Button>
          </Stack>
        )}
        {(dialog?.kind === "recovery" || dialog?.kind === "disable") && (
          <Stack>
            {dialog.kind === "recovery" && (
              <Text size="sm">{t("security.oldCodesInvalid")}</Text>
            )}
            {dialog.kind === "disable" && (
              <Alert color="orange">{t("security.disableWarning")}</Alert>
            )}
            <PasswordInput label={t("security.yourPassword")} value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoFocus />
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
                    notifications.show({ color: "green", message: t("security.disabled") });
                    setDialog(null);
                    load();
                  }
                })
              }
            >
              {dialog.kind === "recovery" ? t("security.generate") : t("security.disable")}
            </Button>
          </Stack>
        )}
        {dialog?.kind === "codes" && (
          <RecoveryCodesView
            codes={dialog.codes}
            doneLabel={t("security.done")}
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
