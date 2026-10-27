// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState } from "react";
import { Alert, Anchor, Button, Center, Group, Input, PasswordInput, Text } from "@mantine/core";
import { IconCircleCheck, IconKey } from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import { useAuth } from "./auth";
import i18n from "./i18n";

// Logowanie SSO (Entra ID): konto bez hasła w panelu potwierdza tożsamość
// ponownym logowaniem u dostawcy w okienku. Serwer zapamiętuje to w sesji na
// kilka minut; pole hasła dostaje wtedy umowną wartość, żeby formularze
// działały bez zmian (serwer ignoruje hasło dla kont SSO).
export const SSO_CONFIRMED = "sso";

// Wynik wraca kanałem BroadcastChannel, nie przez window.opener: panel
// wysyła Cross-Origin-Opener-Policy: same-origin, więc po przejściu okienka
// przez stronę dostawcy połączenie z oknem panelu jest zerwane (opener = null,
// a popup.closed od razu true).
const channelName = "vardr-sso";
const waitFor = 10 * 60 * 1000; // jak ważność rozpoczętego logowania na serwerze

// Strona powrotu w okienku: wynik do panelu i zamknięcie okienka.
export function SsoDone() {
  const { t } = useTranslation();
  const q = new URLSearchParams(window.location.search);
  const result = q.get("result") === "ok" ? "ok" : "error";
  const code = q.get("code") ?? "";
  useEffect(() => {
    try {
      const ch = new BroadcastChannel(channelName);
      ch.postMessage({ result, code });
      ch.close();
    } catch {
      /* stara przeglądarka – wynik zostaje na tej stronie */
    }
    if (result === "ok") window.setTimeout(() => window.close(), 300);
  }, [result, code]);
  return (
    <Center mih="100vh" p="md">
      <Text>
        {result === "ok" ? t("sso.confirmedClose") : ssoError(code)}{" "}
        <Anchor href="/">{t("sso.toPanel")}</Anchor>
      </Text>
    </Center>
  );
}

// Komunikat dla kodu błędu z powrotu od dostawcy (sso_error / code).
export function ssoError(code: string): string {
  return i18n.t(`sso.err.${code}`, { defaultValue: i18n.t("sso.err.failed", { code }) });
}

// Zastąpione przez nowsze okienko – bez komunikatu.
class Superseded extends Error {}
let stopWaiting: (() => void) | null = null;

// Okienko z ponownym logowaniem u dostawcy; kończy się wynikiem z okienka
// (zamknięcia okienka nie da się wykryć – patrz wyżej).
export function confirmSSO(): Promise<void> {
  stopWaiting?.();
  return new Promise((resolve, reject) => {
    const w = 520;
    const h = 680;
    const left = window.screenX + Math.max(0, (window.outerWidth - w) / 2);
    const top = window.screenY + Math.max(0, (window.outerHeight - h) / 2);
    const popup = window.open("/api/v1/auth/oidc/start?reauth=1", "vardr-sso", `popup,width=${w},height=${h},left=${left},top=${top}`);
    if (!popup) {
      reject(new Error(i18n.t("sso.err.popup_blocked")));
      return;
    }
    const ch = new BroadcastChannel(channelName);
    const finish = () => {
      ch.close();
      window.clearTimeout(timer);
      stopWaiting = null;
    };
    ch.onmessage = (e: MessageEvent) => {
      const d = e.data as { result?: string; code?: string };
      finish();
      if (d?.result === "ok") resolve();
      else reject(new Error(ssoError(d?.code ?? "")));
    };
    const timer = window.setTimeout(() => {
      finish();
      reject(new Error(i18n.t("sso.err.cancelled")));
    }, waitFor);
    stopWaiting = () => {
      finish();
      reject(new Superseded());
    };
  });
}

// Pole potwierdzenia operacji: hasło, a dla konta SSO – przycisk z ponownym
// logowaniem u dostawcy. onChange dostaje hasło albo SSO_CONFIRMED.
export function ReauthPassword({
  label,
  value,
  onChange,
  required,
  autoFocus,
  description,
  error,
}: {
  label?: React.ReactNode;
  value: string;
  onChange: (v: string) => void;
  required?: boolean;
  autoFocus?: boolean;
  description?: React.ReactNode;
  error?: React.ReactNode;
}) {
  const { t } = useTranslation();
  const { user } = useAuth();
  const [waiting, setWaiting] = useState(false);
  const [failure, setFailure] = useState("");

  if (user?.source !== "oidc") {
    return (
      <PasswordInput
        label={label}
        description={description}
        error={error}
        required={required}
        autoFocus={autoFocus}
        autoComplete="current-password"
        value={value}
        onChange={(e) => onChange(e.currentTarget.value)}
      />
    );
  }

  const confirm = async () => {
    setWaiting(true);
    setFailure("");
    try {
      await confirmSSO();
      onChange(SSO_CONFIRMED);
      setWaiting(false);
    } catch (err) {
      if (err instanceof Superseded) return;
      setFailure(err instanceof Error ? err.message : String(err));
      setWaiting(false);
    }
  };

  return (
    <Input.Wrapper label={t("sso.reauthLabel")} description={t("sso.reauthHint")} error={error}>
      <Group mt={4} gap="sm">
        {value === SSO_CONFIRMED ? (
          <Group gap={6}>
            <IconCircleCheck size={18} color="var(--mantine-color-green-6)" />
            <Text size="sm">{t("sso.confirmed")}</Text>
          </Group>
        ) : (
          <>
            <Button variant="light" leftSection={<IconKey size={16} />} onClick={() => void confirm()}>
              {t("sso.reauthButton")}
            </Button>
            {waiting && (
              <Text size="xs" c="dimmed">
                {t("sso.waiting")}
              </Text>
            )}
          </>
        )}
      </Group>
      {failure && (
        <Alert color="red" mt="xs" p="xs">
          {failure}
        </Alert>
      )}
    </Input.Wrapper>
  );
}
