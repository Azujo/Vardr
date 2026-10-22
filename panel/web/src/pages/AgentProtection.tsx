// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Code,
  CopyButton,
  Group,
  Modal,
  NumberInput,
  PasswordInput,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconKey, IconShieldCheck } from "@tabler/icons-react";
import {
  agentsApi,
  ago,
  formatDate,
  tamperKinds,
  type AgentStatusDoc,
  type AgentView,
  type UninstallToken,
} from "../api";

const protectionLabels: Record<string, { label: string; color: string; hint: string }> = {
  protected: {
    label: "chroniony",
    color: "green",
    hint: "Administrator komputera nie zatrzyma ani nie odinstaluje agenta bez tokenu z panelu.",
  },
  open: { label: "bez ochrony", color: "red", hint: "Usługa ma zwykłe uprawnienia – agent przywróci ochronę w ciągu 30 s." },
  other: { label: "zmienione uprawnienia", color: "red", hint: "Uprawnienia usługi zmieniono z zewnątrz." },
  error: { label: "błąd", color: "red", hint: "Agent nie może sprawdzić albo ustawić uprawnień usługi." },
  off: { label: "wyłączona", color: "gray", hint: "Ochrona wyłączona w grupie agenta (Grupy agentów)." },
  unknown: {
    label: "nieobsługiwana",
    color: "gray",
    hint: "Agent starszy niż 0.7.0, kolektor albo konektor (bez usługi Windows).",
  },
};

const tokenStates: Record<string, { label: string; color: string }> = {
  active: { label: "ważny", color: "green" },
  used: { label: "użyty", color: "blue" },
  revoked: { label: "unieważniony", color: "gray" },
  expired: { label: "wygasł", color: "gray" },
};

export function AgentProtection({ agent, status, admin }: { agent: AgentView; status: AgentStatusDoc; admin: boolean }) {
  const [tokens, setTokens] = useState<UninstallToken[]>([]);
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [hours, setHours] = useState<number | string>(24);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState<{ token: string; item: UninstallToken } | null>(null);

  const load = useCallback(() => {
    if (!admin) return;
    agentsApi
      .uninstallTokens(agent.id)
      .then((r) => setTokens(r.tokens))
      .catch(() => setTokens([]));
  }, [admin, agent.id]);
  useEffect(load, [load]);

  const create = async () => {
    setBusy(true);
    try {
      const r = await agentsApi.createUninstallToken(agent.id, { reason, hours: Number(hours) || 24, password });
      setIssued(r);
      setPassword("");
      setReason("");
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (t: UninstallToken) => {
    if (!window.confirm(`Unieważnić token ${t.token_id}?`)) return;
    try {
      await agentsApi.revokeUninstallToken(agent.id, t.id);
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    }
  };

  const close = () => {
    setOpen(false);
    setIssued(null);
    setPassword("");
  };

  const state = protectionLabels[agent.protection ?? "unknown"] ?? protectionLabels.unknown;
  const events = [...(status.protection?.events ?? [])].reverse();
  return (
    <Card withBorder>
      <Group justify="space-between" mb="sm">
        <Group gap="xs">
          <IconShieldCheck size={20} />
          <Title order={4}>Ochrona agenta</Title>
          <Badge color={state.color} variant="light">
            {state.label}
          </Badge>
        </Group>
        {admin && (
          <Button size="xs" variant="light" leftSection={<IconKey size={14} />} onClick={() => setOpen(true)}>
            Token deinstalacji
          </Button>
        )}
      </Group>
      <Text size="sm" c="dimmed">
        {state.hint}
        {agent.protection_error ? ` ${agent.protection_error}` : ""}
        {status.protection?.enabled ? ` Ważne tokeny znane agentowi: ${status.protection.tokens}.` : ""}
      </Text>

      {events.length > 0 && (
        <Table.ScrollContainer minWidth={600} mt="sm">
          <Table verticalSpacing={4}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Kiedy</Table.Th>
                <Table.Th>Zdarzenie</Table.Th>
                <Table.Th>Konto</Table.Th>
                <Table.Th>Szczegóły</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {events.map((e) => {
                const k = tamperKinds[e.kind] ?? { title: e.kind, level: "" };
                return (
                  <Table.Tr key={e.id}>
                    <Table.Td>
                      <Text size="sm">{formatDate(e.at)}</Text>
                      <Text size="xs" c="dimmed">
                        {ago(e.at)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge color={k.level === "high" ? "red" : k.level ? "orange" : "gray"} variant="light">
                        {k.title}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{e.user || "—"}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">
                        {e.detail || ""}
                        {e.token_id ? ` token ${e.token_id}` : ""}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}

      {admin && tokens.length > 0 && (
        <Table.ScrollContainer minWidth={600} mt="sm">
          <Table verticalSpacing={4}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Token</Table.Th>
                <Table.Th>Stan</Table.Th>
                <Table.Th>Wygenerował</Table.Th>
                <Table.Th>Powód</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {tokens.map((t) => (
                <Table.Tr key={t.id}>
                  <Table.Td>
                    <Text size="sm" ff="monospace">
                      {t.token_id}
                    </Text>
                    <Text size="xs" c="dimmed">
                      ważny do {formatDate(t.expires_at)}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Badge color={tokenStates[t.state]?.color} variant="light">
                      {tokenStates[t.state]?.label}
                    </Badge>
                    {t.used_at && (
                      <Text size="xs" c="dimmed">
                        {t.used_action === "uninstall_token" ? "deinstalacja" : t.used_action === "upgrade" ? "aktualizacja" : "zatrzymanie"}{" "}
                        {formatDate(t.used_at)}
                        {t.used_by ? ` (${t.used_by})` : ""}
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{t.created_by}</Text>
                    <Text size="xs" c="dimmed">
                      {formatDate(t.created_at)}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{t.reason}</Text>
                  </Table.Td>
                  <Table.Td>
                    {t.state === "active" && (
                      <Button size="compact-xs" variant="subtle" color="red" onClick={() => void revoke(t)}>
                        Unieważnij
                      </Button>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}

      <Modal opened={open} onClose={close} title={`Token deinstalacji – ${agent.hostname || agent.id}`} size="lg">
        {issued ? (
          <Stack>
            <Alert color="yellow" title="Token widać tylko teraz">
              Zapisz go albo przekaż osobie, która wykona prace na komputerze. Panel przechowuje tylko skrót. Token jest
              jednorazowy i działa wyłącznie na tym komputerze do {formatDate(issued.item.expires_at)}.
            </Alert>
            <Group>
              <Code fz="lg" fw={700}>
                {issued.token}
              </Code>
              <CopyButton value={issued.token}>
                {({ copied, copy }) => (
                  <Button size="xs" variant="light" onClick={copy}>
                    {copied ? "Skopiowano" : "Kopiuj"}
                  </Button>
                )}
              </CopyButton>
            </Group>
            <Text size="sm">Na komputerze (PowerShell jako administrator):</Text>
            <Code block>
              {`vardr-agent stop -token ${issued.token}        # prace serwisowe (start: vardr-agent start)
vardr-agent uninstall -token ${issued.token}   # deinstalacja
msiexec /x vardr-agent.msi /qn UNINSTALL_TOKEN=${issued.token}`}
            </Code>
            <Text size="xs" c="dimmed">
              Agent pobiera skrót tokenu z panelu – polecenie z tokenem samo odświeża konfigurację, więc działa od razu.
            </Text>
            <Button onClick={close}>Zamknij</Button>
          </Stack>
        ) : (
          <Stack>
            <Text size="sm">
              Jednorazowy token pozwala zatrzymać albo odinstalować agenta na tym jednym komputerze. Nowy token unieważnia
              poprzedni niewykorzystany. Wygenerowanie trafia do audytu.
            </Text>
            <TextInput
              label="Powód"
              placeholder="np. ZGL-123 reinstalacja systemu"
              value={reason}
              onChange={(e) => setReason(e.currentTarget.value)}
              required
            />
            <NumberInput label="Ważność (godziny)" min={1} max={168} value={hours} onChange={setHours} w={200} />
            <PasswordInput
              label="Twoje hasło"
              description="Token osłabia ochronę komputera – potwierdź hasłem."
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
              required
            />
            <Button loading={busy} disabled={reason.trim().length < 3 || !password} onClick={() => void create()}>
              Wygeneruj token
            </Button>
          </Stack>
        )}
      </Modal>
    </Card>
  );
}
