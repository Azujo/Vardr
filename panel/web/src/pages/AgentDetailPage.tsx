import { useEffect, useState } from "react";
import {
  Alert,
  Anchor,
  Badge,
  Button,
  Card,
  Code,
  Collapse,
  Group,
  List,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconArrowLeft, IconCertificateOff, IconTrash } from "@tabler/icons-react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  agentsApi,
  ago,
  configStateLabels,
  enrollApi,
  formatDate,
  formatNumber,
  groupsApi,
  type AgentGroup,
  type AgentStatusDoc,
  type AgentView,
} from "../api";
import { limitsSummary, profileLabels } from "./GroupsPage";
import { useAuth } from "../auth";
import { StateBadge } from "./AgentsPage";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
        {label}
      </Text>
      <Text size="sm" component="div">
        {children}
      </Text>
    </div>
  );
}

const channelState: Record<string, { label: string; color: string }> = {
  ok: { label: "działa", color: "green" },
  starting: { label: "uruchamianie", color: "blue" },
  not_found: { label: "brak kanału", color: "gray" },
  access_denied: { label: "brak dostępu", color: "red" },
  error: { label: "błąd", color: "red" },
};

function duration(ns?: number): string {
  if (!ns) return "—";
  const s = ns / 1e9;
  if (s < 1) return `${Math.round(s * 1000)} ms`;
  if (s < 120) return `${s.toFixed(1)} s`;
  if (s < 7200) return `${Math.round(s / 60)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

export default function AgentDetailPage() {
  const { id = "" } = useParams();
  const { user } = useAuth();
  const navigate = useNavigate();
  const [agent, setAgent] = useState<AgentView | null>(null);
  const [status, setStatus] = useState<AgentStatusDoc>({});
  const [error, setError] = useState("");
  const [raw, setRaw] = useState(false);
  const [groups, setGroups] = useState<AgentGroup[]>([]);
  useEffect(() => {
    groupsApi
      .list()
      .then((r) => setGroups(r.groups))
      .catch(() => setGroups([]));
  }, []);

  const changeGroup = async (groupId: number) => {
    try {
      await groupsApi.assign(id, groupId);
      const r = await agentsApi.get(id);
      setAgent(r.agent);
      notifications.show({ color: "green", message: "Zmieniono grupę – agent pobierze nową konfigurację w ciągu ok. 5 minut." });
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    }
  };

  useEffect(() => {
    const load = () =>
      agentsApi
        .get(id)
        .then((r) => {
          setAgent(r.agent);
          setStatus(r.status);
          setError("");
        })
        .catch((e) => setError(e instanceof Error ? e.message : String(e)));
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [id]);

  const remove = async () => {
    if (!window.confirm(`Usunąć agenta ${id} z listy? Jeśli nadal działa, pojawi się ponownie po kolejnym heartbeacie.`))
      return;
    try {
      await agentsApi.remove(id);
      notifications.show({ color: "green", message: `Usunięto ${id} z listy` });
      navigate("/agents");
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    }
  };

  const revokeCert = async () => {
    const reason = window.prompt(
      `Unieważnić certyfikaty agenta ${id}? Agent natychmiast straci dostęp do serwera (np. zgubiony laptop).

Powód:`,
      "zgubiony lub wycofany komputer",
    );
    if (reason === null) return;
    try {
      const r = await enrollApi.revokeAgent(id, reason);
      notifications.show({
        color: r.revoked ? "green" : "yellow",
        message: r.revoked
          ? `Unieważniono certyfikaty: ${r.revoked}. Agent nie połączy się już z serwerem.`
          : "Brak certyfikatów wystawionych przez panel (agent z paczki laboratoryjnej).",
      });
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    }
  };

  const back = (
    <Anchor component={Link} to="/agents" size="sm">
      <Group gap={4}>
        <IconArrowLeft size={14} /> Wszyscy agenci
      </Group>
    </Anchor>
  );
  if (error)
    return (
      <Stack>
        {back}
        <Alert color="red">{error}</Alert>
      </Stack>
    );
  if (!agent) return back;

  const c = status.counters ?? {};
  const p = status.process ?? {};
  return (
    <Stack>
      {back}
      <Group justify="space-between" align="flex-start">
        <div>
          <Group gap="sm">
            <Title order={2}>{agent.hostname || agent.id}</Title>
            <StateBadge a={agent} />
          </Group>
          <Text c="dimmed" size="sm">
            {agent.id} · {agent.os || "system nieznany"} · agent {agent.version || "?"}
          </Text>
        </div>
        {user?.role === "admin" && (
          <Group gap="xs">
            <Button variant="light" color="red" leftSection={<IconCertificateOff size={16} />} onClick={() => void revokeCert()}>
              Unieważnij certyfikat
            </Button>
            <Button variant="default" leftSection={<IconTrash size={16} />} onClick={() => void remove()}>
              Usuń z listy
            </Button>
          </Group>
        )}
      </Group>

      {agent.problems.length > 0 && (
        <Alert color="orange" title="Wymaga uwagi">
          <List size="sm">
            {agent.problems.map((pr) => (
              <List.Item key={pr}>{pr}</List.Item>
            ))}
          </List>
        </Alert>
      )}

      <Card withBorder>
        <Group justify="space-between" align="flex-start" wrap="wrap">
          <div>
            <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
              Konfiguracja z panelu
            </Text>
            <Group gap="xs" mt={4}>
              <Badge variant="light" color={configStateLabels[agent.config_state]?.color}>
                {configStateLabels[agent.config_state]?.label}
              </Badge>
              <Text size="sm" c="dimmed">
                {configStateLabels[agent.config_state]?.hint}
              </Text>
            </Group>
            {(() => {
              const g = groups.find((x) => x.id === agent.group_id);
              return g ? (
                <Text size="sm" mt={6}>
                  {profileLabels[g.profile]} · {limitsSummary(g.limits)}
                </Text>
              ) : null;
            })()}
            <Text size="xs" c="dimmed" ff="monospace" mt={4}>
              wersja oczekiwana {agent.config_expected}
              {agent.config_applied ? ` · zastosowana ${agent.config_applied}` : ""}
            </Text>
          </div>
          {user?.role === "admin" ? (
            <Select
              label="Grupa"
              w={240}
              data={groups.map((g) => ({ value: String(g.id), label: g.name }))}
              value={String(agent.group_id)}
              allowDeselect={false}
              onChange={(v) => v && Number(v) !== agent.group_id && void changeGroup(Number(v))}
            />
          ) : (
            <Text size="sm">Grupa: {agent.group}</Text>
          )}
        </Group>
      </Card>

      <Card withBorder>
        <SimpleGrid cols={{ base: 2, md: 4 }} spacing="lg">
          <Field label="Ostatni sygnał">
            {ago(agent.last_seen)} <Text span size="xs" c="dimmed">({formatDate(agent.last_seen)})</Text>
          </Field>
          <Field label="Adres IP">{agent.remote_ip || "—"}</Field>
          <Field label="Działa od">{agent.started_at ? `${formatDate(agent.started_at)} (${ago(agent.started_at)})` : "—"}</Field>
          <Field label="Pierwszy raz widziany">{formatDate(agent.first_seen)}</Field>
          <Field label="Wysyłka do serwera">
            {status.server?.healthy ? (
              <Badge color="green" variant="light">działa</Badge>
            ) : (
              <Badge color="red" variant="light">błąd</Badge>
            )}
          </Field>
          <Field label="Ostatnia przyjęta paczka">{ago(status.server?.last_accepted_at)}</Field>
          <Field label="Certyfikat ważny do">
            {agent.cert_not_after ? `${formatDate(agent.cert_not_after)} (${agent.cert_days_left} dni)` : "—"}
          </Field>
          <Field label="Ostatni błąd wysyłki">
            {status.server?.last_error ? `${status.server.last_error} (${ago(status.server.last_error_at)})` : "—"}
          </Field>
        </SimpleGrid>
      </Card>

      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Card withBorder>
          <Title order={4} mb="sm">
            Zdarzenia (od startu agenta)
          </Title>
          <SimpleGrid cols={3} spacing="md">
            <Field label="Odczytane">{formatNumber(c.read)}</Field>
            <Field label="Przyjęte">{formatNumber(c.accepted)}</Field>
            <Field label="Odfiltrowane">{formatNumber(c.filtered)}</Field>
            <Field label="Ponowienia">{formatNumber(c.retries)}</Field>
            <Field label="Przycięte">{formatNumber(c.truncated)}</Field>
            <Field label="Kwarantanna">{formatNumber(c.quarantined)}</Field>
          </SimpleGrid>
        </Card>
        <Card withBorder>
          <Title order={4} mb="sm">
            Zasoby agenta
          </Title>
          <SimpleGrid cols={3} spacing="md">
            <Field label="Czas CPU">{duration(p.cpu_time_ns)}</Field>
            <Field label="Pamięć (sterta)">{p.heap_mb !== undefined ? `${p.heap_mb.toFixed(1)} MB` : "—"}</Field>
            <Field label="Pamięć (system)">{p.sys_mb !== undefined ? `${p.sys_mb.toFixed(1)} MB` : "—"}</Field>
            <Field label="Dławienie EPS">{duration(status.throttle?.eps_ns)}</Field>
            <Field label="Dławienie łącza">{duration(status.throttle?.bandwidth_ns)}</Field>
            <Field label="Wątki Go">{p.goroutines ?? "—"}</Field>
          </SimpleGrid>
        </Card>
      </SimpleGrid>

      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Card withBorder>
          <Title order={4} mb="sm">
            Bufor dyskowy
          </Title>
          {!status.buffer ? (
            <Text size="sm" c="dimmed">
              Agent starszy niż 0.6.0 – bez bufora dyskowego.
            </Text>
          ) : status.buffer.disabled ? (
            <Text size="sm">Wyłączony – przy braku łączności zdarzenia czekają w dzienniku Windows.</Text>
          ) : (
            <SimpleGrid cols={3} spacing="md">
              <Field label="W buforze">
                {status.buffer.batches} paczek, {(status.buffer.bytes / 1048576).toFixed(1)} MB
              </Field>
              <Field label="Limit">{Math.round(status.buffer.max_bytes / 1048576)} MB</Field>
              <Field label="Po zapełnieniu">{status.buffer.on_full === "drop_oldest" ? "usuwa najstarsze" : "wstrzymuje odczyt"}</Field>
              <Field label="Najstarsza paczka">{status.buffer.oldest_at ? ago(status.buffer.oldest_at) : "—"}</Field>
              <Field label="Buforowane od startu">{formatNumber(status.buffer.spooled_events)} zdarzeń</Field>
              <Field label="Utracone">
                {status.buffer.dropped_events > 0 ? (
                  <Text c="red" size="sm">
                    {formatNumber(status.buffer.dropped_events)} zdarzeń
                  </Text>
                ) : (
                  "0"
                )}
              </Field>
            </SimpleGrid>
          )}
        </Card>
        <Card withBorder>
          <Title order={4} mb="sm">
            Zegar
          </Title>
          {!status.clock?.measured_at && !status.clock?.time_service ? (
            <Text size="sm" c="dimmed">
              Agent starszy niż 0.6.0 albo jeszcze bez pomiaru.
            </Text>
          ) : (
            <SimpleGrid cols={3} spacing="md">
              <Field label="Odchylenie od serwera">
                {status.clock?.measured_at
                  ? `${status.clock.offset_ms > 0 ? "+" : ""}${(status.clock.offset_ms / 1000).toFixed(1)} s (±${status.clock.uncertainty_ms} ms)`
                  : "—"}
              </Field>
              <Field label="Pomiar">{ago(status.clock?.measured_at)}</Field>
              <Field label="Usługa czasu Windows">
                {status.clock?.time_service === "running" ? (
                  <Badge color="green" variant="light">działa</Badge>
                ) : (
                  <Badge color="red" variant="light">{status.clock?.time_service ?? "—"}</Badge>
                )}
              </Field>
            </SimpleGrid>
          )}
        </Card>
      </SimpleGrid>

      <Card withBorder>
        <Title order={4} mb="sm">
          Kanały
        </Title>
        <Table.ScrollContainer minWidth={640}>
          <Table verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Kanał</Table.Th>
                <Table.Th>Stan</Table.Th>
                <Table.Th>Ostatni rekord</Table.Th>
                <Table.Th>Odczyt</Table.Th>
                <Table.Th>Opóźnienie</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {(status.channels ?? []).map((ch) => {
                const s = channelState[ch.state] ?? { label: ch.state, color: "gray" };
                return (
                  <Table.Tr key={ch.name}>
                    <Table.Td>
                      <Text size="sm" fw={500}>
                        {ch.name}
                      </Text>
                      {ch.error && (
                        <Text size="xs" c="red">
                          {ch.error}
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Badge color={s.color} variant="light">
                        {s.label}
                      </Badge>
                    </Table.Td>
                    <Table.Td>{formatNumber(ch.last_record_id)}</Table.Td>
                    <Table.Td>{ago(ch.last_read_at)}</Table.Td>
                    <Table.Td>{duration(ch.last_lag_ns)}</Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Card>

      <Card withBorder>
        <Title order={4} mb="sm">
          Ostrzeżenia agenta
        </Title>
        {(status.warnings ?? []).length === 0 ? (
          <Text size="sm" c="dimmed">
            Brak ostrzeżeń.
          </Text>
        ) : (
          <List size="sm" spacing={4}>
            {[...(status.warnings ?? [])].reverse().map((w, i) => (
              <List.Item key={i}>{w}</List.Item>
            ))}
          </List>
        )}
      </Card>

      <div>
        <Button variant="subtle" size="xs" onClick={() => setRaw((r) => !r)}>
          {raw ? "Ukryj" : "Pokaż"} pełny status (JSON)
        </Button>
        <Collapse in={raw}>
          <Code block mt="xs">
            {JSON.stringify(status, null, 2)}
          </Code>
        </Collapse>
      </div>
    </Stack>
  );
}
