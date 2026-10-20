import { useState } from "react";
import { Alert, Button, Center, Paper, PasswordInput, Stack, Text, TextInput, Title } from "@mantine/core";
import { IconAlertCircle, IconShieldHalf } from "@tabler/icons-react";
import { useAuth } from "../auth";

export default function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await login(username, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setPassword("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Center mih="100vh" p="md">
      <Paper withBorder shadow="md" p="xl" w={380} maw="100%">
        <form onSubmit={submit}>
          <Stack>
            <Stack gap={4} align="center">
              <IconShieldHalf size={48} color="var(--mantine-color-yellow-5)" />
              <Title order={2}>Vardr</Title>
              <Text c="dimmed" size="sm">
                Hliðskjálf – panel SIEM
              </Text>
            </Stack>
            {error && (
              <Alert color="red" icon={<IconAlertCircle size={18} />}>
                {error}
              </Alert>
            )}
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
      </Paper>
    </Center>
  );
}
