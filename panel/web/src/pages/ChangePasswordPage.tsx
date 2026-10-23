// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from "react";
import { Alert, Button, Center, Paper, PasswordInput, Stack, Text, Title } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAlertCircle } from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useAuth } from "../auth";

const MIN = 12;

export default function ChangePasswordPage({ forced = false }: { forced?: boolean }) {
  const { t } = useTranslation("account");
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
      notifications.show({ color: "green", message: t("password.changed") });
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
          <Title order={3}>{forced ? t("password.titleForced") : t("password.title")}</Title>
          <Text c="dimmed" size="sm">
            {forced ? t("password.introForced") : t("password.intro", { min: MIN })}
          </Text>
        </div>
        {error && (
          <Alert color="red" icon={<IconAlertCircle size={18} />}>
            {error}
          </Alert>
        )}
        <PasswordInput
          label={t("password.current")}
          autoComplete="current-password"
          required
          value={current}
          onChange={(e) => setCurrent(e.currentTarget.value)}
        />
        <PasswordInput
          label={t("password.new")}
          description={t("password.newHint", { min: MIN })}
          autoComplete="new-password"
          required
          value={next}
          error={tooShort ? t("password.tooShort", { len: [...next].length, min: MIN }) : undefined}
          onChange={(e) => setNext(e.currentTarget.value)}
        />
        <PasswordInput
          label={t("password.repeat")}
          autoComplete="new-password"
          required
          value={repeat}
          error={mismatch ? t("password.mismatch") : undefined}
          onChange={(e) => setRepeat(e.currentTarget.value)}
        />
        <Button type="submit" loading={busy} disabled={mismatch || tooShort}>
          {t("password.submit")}
        </Button>
        {forced && (
          <Button variant="subtle" color="gray" onClick={() => void logout()}>
            {t("common:header.logout")}
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
