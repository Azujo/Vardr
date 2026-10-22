// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from "react";
import { Alert, Button, Center, Paper, PasswordInput, Stack, Text, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAlertCircle } from "@tabler/icons-react";
import { api } from "../api";
import { useAuth } from "../auth";

const MIN = 12;

export default function ChangePasswordPage({ forced = false }: { forced?: boolean }) {
  const { applySession, logout } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const mismatch = repeat !== "" && next !== repeat;
  const tooShort = next !== "" && [...next].length < MIN;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (mismatch || tooShort) return;
    setBusy(true);
    setError("");
    try {
      applySession(await api.changePassword(current, next));
      notifications.show({ color: "green", message: "Hasło zmienione. Inne sesje tego konta zostały zakończone." });
      setCurrent("");
      setNext("");
      setRepeat("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const form = (
    <form onSubmit={submit}>
      <Stack>
        <div>
          <Title order={3}>{forced ? "Ustaw własne hasło" : "Zmiana hasła"}</Title>
          <Text c="dimmed" size="sm">
            {forced
              ? "Logujesz się hasłem startowym – przed dalszą pracą ustaw własne."
              : `Co najmniej ${MIN} znaków; najlepiej kilka słów, które łatwo zapamiętać.`}
          </Text>
        </div>
        {error && (
          <Alert color="red" icon={<IconAlertCircle size={18} />}>
            {error}
          </Alert>
        )}
        <PasswordInput
          label="Obecne hasło"
          autoComplete="current-password"
          required
          value={current}
          onChange={(e) => setCurrent(e.currentTarget.value)}
        />
        <PasswordInput
          label="Nowe hasło"
          description={`minimum ${MIN} znaków, bez nazwy użytkownika`}
          autoComplete="new-password"
          required
          value={next}
          error={tooShort ? `za krótkie (${[...next].length}/${MIN})` : undefined}
          onChange={(e) => setNext(e.currentTarget.value)}
        />
        <PasswordInput
          label="Powtórz nowe hasło"
          autoComplete="new-password"
          required
          value={repeat}
          error={mismatch ? "hasła się różnią" : undefined}
          onChange={(e) => setRepeat(e.currentTarget.value)}
        />
        <Button type="submit" loading={busy} disabled={mismatch || tooShort}>
          Zmień hasło
        </Button>
        {forced && (
          <Button variant="subtle" color="gray" onClick={() => void logout()}>
            Wyloguj
          </Button>
        )}
      </Stack>
    </form>
  );

  return forced ? (
    <Center mih="100vh" p="md">
      <Paper withBorder shadow="md" p="xl" w={420} maw="100%">
        {form}
      </Paper>
    </Center>
  ) : (
    <Paper withBorder p="xl" maw={480}>
      {form}
    </Paper>
  );
}
