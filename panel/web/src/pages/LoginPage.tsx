import { useState } from "react";
import { Alert, Anchor, Button, Center, Paper, PasswordInput, Stack, Text, TextInput, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAlertCircle, IconShieldHalf } from "@tabler/icons-react";
import { api, isMFAStep, type LoginFinal, type MFASetup } from "../api";
import { useAuth } from "../auth";
import { CodeInput, MFASetupView, RecoveryCodesView } from "../mfa";

// Logowanie: hasło, a gdy konto ma drugi składnik albo polityka go wymaga –
// kod z aplikacji (albo pierwsza konfiguracja aplikacji i kody zapasowe).
type Step =
  | { kind: "password" }
  | { kind: "code"; challenge: string; username: string }
  | { kind: "enroll"; challenge: string; username: string; setup?: MFASetup }
  | { kind: "codes"; result: LoginFinal };

export default function LoginPage() {
  const { applySession, notice } = useAuth();
  const [step, setStep] = useState<Step>({ kind: "password" });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const finish = (r: LoginFinal) => {
    if (r.recovery_codes?.length) {
      setStep({ kind: "codes", result: r });
      return;
    }
    if (r.mfa_method === "recovery") {
      notifications.show({
        color: r.recovery_left ? "yellow" : "red",
        autoClose: false,
        message: `Użyto kodu zapasowego – zostało ${r.recovery_left ?? 0}. Wygeneruj nowe w „Bezpieczeństwie konta”.`,
      });
    }
    applySession(r);
  };

  const fail = (err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err);
    setError(msg);
    setCode("");
    if (msg.includes("wygasło")) setStep({ kind: "password" });
  };

  const submitPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const r = await api.login(username, password);
      setPassword("");
      if (!isMFAStep(r)) {
        finish(r);
      } else if (r.mfa === "code") {
        setStep({ kind: "code", challenge: r.challenge, username: r.username });
      } else {
        const setup = await api.loginEnroll(r.challenge);
        setStep({ kind: "enroll", challenge: r.challenge, username: r.username, setup });
      }
    } catch (err) {
      setPassword("");
      fail(err);
    } finally {
      setBusy(false);
    }
  };

  const submitCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (step.kind !== "code" && step.kind !== "enroll") return;
    setBusy(true);
    setError("");
    try {
      finish(step.kind === "code" ? await api.loginMFA(step.challenge, code) : await api.loginEnrollConfirm(step.challenge, code));
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  };

  const back = (
    <Anchor
      component="button"
      type="button"
      size="xs"
      onClick={() => {
        setStep({ kind: "password" });
        setError("");
        setCode("");
      }}
    >
      ← inne konto / od nowa
    </Anchor>
  );

  return (
    <Center mih="100vh" p="md">
      <Paper withBorder shadow="md" p="xl" w={step.kind === "password" || step.kind === "code" ? 380 : 460} maw="100%">
        <Stack>
          <Stack gap={4} align="center">
            <IconShieldHalf size={48} color="var(--mantine-color-yellow-5)" />
            <Title order={2}>Vardr</Title>
            <Text c="dimmed" size="sm">
              Hliðskjálf – panel SIEM
            </Text>
          </Stack>
          {notice && step.kind === "password" && (
            <Alert color="yellow" icon={<IconAlertCircle size={18} />}>
              {notice}
            </Alert>
          )}
          {error && (
            <Alert color="red" icon={<IconAlertCircle size={18} />}>
              {error}
            </Alert>
          )}

          {step.kind === "password" && (
            <form onSubmit={submitPassword}>
              <Stack>
                <TextInput
                  label="Login"
                  autoComplete="username"
                  autoFocus
                  required
                  value={username}
                  onChange={(e) => setUsername(e.currentTarget.value)}
                />
                <PasswordInput
                  label="Hasło"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.currentTarget.value)}
                />
                <Button type="submit" loading={busy} fullWidth>
                  Zaloguj
                </Button>
              </Stack>
            </form>
          )}

          {step.kind === "code" && (
            <form onSubmit={submitCode}>
              <Stack>
                <Text size="sm">
                  Konto <b>{step.username}</b>: podaj kod z aplikacji uwierzytelniającej.
                </Text>
                <CodeInput value={code} onChange={setCode} allowRecovery />
                <Button type="submit" loading={busy} fullWidth>
                  Potwierdź
                </Button>
                {back}
              </Stack>
            </form>
          )}

          {step.kind === "enroll" && step.setup && (
            <form onSubmit={submitCode}>
              <Stack>
                <Alert color="blue">
                  Panel wymaga drugiego składnika logowania. Skonfiguruj aplikację uwierzytelniającą dla konta{" "}
                  <b>{step.username}</b> – to jednorazowe.
                </Alert>
                <MFASetupView setup={step.setup} />
                <CodeInput value={code} onChange={setCode} autoFocus={false} />
                <Button type="submit" loading={busy} fullWidth>
                  Włącz i zaloguj
                </Button>
                {back}
              </Stack>
            </form>
          )}

          {step.kind === "codes" && (
            <RecoveryCodesView codes={step.result.recovery_codes ?? []} doneLabel="Przejdź do panelu" onDone={() => applySession(step.result)} />
          )}
        </Stack>
      </Paper>
    </Center>
  );
}
