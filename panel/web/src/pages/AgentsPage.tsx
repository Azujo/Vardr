import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Group,
  SegmentedControl,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { IconAlertTriangle, IconCircleCheck, IconDownload, IconPlugConnectedX, IconSearch, IconServer } from "@tabler/icons-react";
import { notifications } from "@mantine/notifications";
import { Link } from "react-router-dom";
import { agentsApi, ago, configStateLabels, enrollApi, formatNumber, type AgentView, type AgentsSummary } from "../api";
import { useAuth } from "../auth";

type Filter = "all" | "online" | "offline" | "problems";

function StatCard({ label, value, color, icon }: { label: string; value: number; color: string; icon: React.ReactNode }) {
  return (
    <Card withBorder padding="md">
      <Group justify="space-between">
        <div>
          <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
            {label}
          </Text>
          <Text fz={28} fw={700} c={color}>
            {value}
          </Text>
        </div>
        {icon}
      </Group>
    </Card>
  );
}

export function StateBadge({ a }: { a: AgentView }) {
  if (a.state === "offline") {
    if (a.stopping === "stop") return <Badge color="red">zatrzymany bez tokenu</Badge>;
    if (a.stopping && a.stopping !== "shutdown") return <Badge color="gray">zatrzymany</Badge>;
    return <Badge color="gray">offline</Badge>;
  }
  if (a.tamper_24h) return <Badge color="red">próba sabotażu</Badge>;
  if (a.problems.length > 0) return <Badge color="orange">problemy</Badge>;
  return <Badge color="green">online</Badge>;
}

export default function AgentsPage() {
  const { user } = useAuth();
  const [downloading, setDownloading] = useState(false);
  const [agents, setAgents] = useState<AgentView[]>([]);
  const [summary, setSummary] = useState<AgentsSummary | null>(null);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [, setTick] = useState(0);

  useEffect(() => {
    const load = () =>
      agentsApi
        .list()
        .then((r) => {
          setAgents(r.agents);
          setSummary(r.summary);
          setError("");
        })
        .catch((e) => setError(e instanceof Error ? e.message : String(e)));
    load();
    // Odświeżanie listy co 15 s i „x s temu” co 5 s.
    const data = setInterval(load, 15000);
    const clock = setInterval(() => setTick((t) => t + 1), 5000);
    return () => {
      clearInterval(data);
      clearInterval(clock);
    };
  }, []);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return agents.filter((a) => {
      if (filter === "online" && a.state !== "online") return false;
      if (filter === "offline" && a.state !== "offline") return false;
      if (filter === "problems" && a.problems.length === 0) return false;
      return !q || [a.id, a.hostname, a.remote_ip, a.version, a.os, a.group].some((v) => v.toLowerCase().includes(q));
    });
  }, [agents, query, filter]);

  const updateMSI = async () => {
    setDownloading(true);
    try {
      await enrollApi.downloadUpdateMSI();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setDownloading(false);
    }
  };

  return (
    <Stack>
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>Huginn – agenci</Title>
          <Text c="dimmed" size="sm">
            Stan agentów z heartbeatu (co minutę). Agent bez sygnału przez 3 minuty jest oznaczany jako offline.
          </Text>
        </div>
        {user?.role === "admin" && (
          <Tooltip
            multiline
            w={360}
            label="Instalator najnowszej wersji agenta bez tokenu: podwójne kliknięcie na komputerze z agentem albo wdrożenie GPO/Intune podmienia wersję, rejestracja i ustawienia zostają. Nowych komputerów nim nie zarejestrujesz (Bifröst → token)."
          >
            <Button variant="light" leftSection={<IconDownload size={16} />} loading={downloading} onClick={() => void updateMSI()}>
              Pobierz aktualizację agenta (MSI)
            </Button>
          </Tooltip>
        )}
      </Group>
      {error && <Alert color="red">{error}</Alert>}

      {summary && (
        <SimpleGrid cols={{ base: 2, md: 4 }}>
          <StatCard label="Agenci" value={summary.total} color="indigo" icon={<IconServer size={28} opacity={0.5} />} />
          <StatCard label="Online" value={summary.online} color="green" icon={<IconCircleCheck size={28} opacity={0.5} />} />
          <StatCard
            label="Offline"
            value={summary.offline}
            color={summary.offline ? "gray" : "dimmed"}
            icon={<IconPlugConnectedX size={28} opacity={0.5} />}
          />
          <StatCard
            label="Z problemami"
            value={summary.with_problems}
            color={summary.with_problems ? "orange" : "dimmed"}
            icon={<IconAlertTriangle size={28} opacity={0.5} />}
          />
        </SimpleGrid>
      )}

      <Group justify="space-between" wrap="wrap">
        <TextInput
          placeholder="Szukaj: agent, host, IP, wersja, grupa"
          leftSection={<IconSearch size={16} />}
          value={query}
          onChange={(e) => setQuery(e.currentTarget.value)}
          w={320}
          maw="100%"
        />
        <SegmentedControl
          value={filter}
          onChange={(v) => setFilter(v as Filter)}
          data={[
            { value: "all", label: "Wszyscy" },
            { value: "online", label: "Online" },
            { value: "offline", label: "Offline" },
            { value: "problems", label: "Problemy" },
          ]}
        />
      </Group>

      {agents.length === 0 && !error ? (
        <Alert color="blue" title="Brak agentów">
          Agenci pojawią się tu po pierwszym heartbeacie. Wymagany agent w wersji 0.4.0 lub nowszej (starsze wersje
          wysyłają zdarzenia, ale nie raportują stanu).
        </Alert>
      ) : (
        <Table.ScrollContainer minWidth={900}>
          <Table striped highlightOnHover verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Stan</Table.Th>
                <Table.Th>Agent</Table.Th>
                <Table.Th>Adres IP</Table.Th>
                <Table.Th>Grupa</Table.Th>
                <Table.Th>Wersja</Table.Th>
                <Table.Th>Ostatni sygnał</Table.Th>
                <Table.Th>Zdarzenia</Table.Th>
                <Table.Th>Kanały</Table.Th>
                <Table.Th>Problemy</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {shown.map((a) => (
                <Table.Tr key={a.id}>
                  <Table.Td>
                    <StateBadge a={a} />
                  </Table.Td>
                  <Table.Td>
                    <Text component={Link} to={`/agents/${encodeURIComponent(a.id)}`} fw={600} c="indigo">
                      {a.hostname || a.id}
                    </Text>
                    <Text size="xs" c="dimmed">
                      {a.id}
                      {a.os ? ` · ${a.os}` : ""}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" ff="monospace">
                      {a.remote_ip || "—"}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{a.group}</Text>
                    <Tooltip label={configStateLabels[a.config_state]?.hint}>
                      <Badge size="xs" variant="light" color={configStateLabels[a.config_state]?.color}>
                        konfiguracja {configStateLabels[a.config_state]?.label}
                      </Badge>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td>{a.version || "—"}</Table.Td>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>
                    <Tooltip label={new Date(a.last_seen).toLocaleString("pl-PL")}>
                      <Text size="sm">{ago(a.last_seen)}</Text>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{formatNumber(a.events_accepted)}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c={a.channels_ok < a.channels_total ? "orange" : undefined}>
                      {a.channels_ok}/{a.channels_total}
                    </Text>
                  </Table.Td>
                  <Table.Td maw={320}>
                    {a.problems.length === 0 ? (
                      <Text size="sm" c="dimmed">
                        —
                      </Text>
                    ) : (
                      <Tooltip label={a.problems.join("\n")} multiline maw={400} style={{ whiteSpace: "pre-line" }}>
                        <Text size="sm" c="orange" lineClamp={2}>
                          {a.problems.join("; ")}
                        </Text>
                      </Tooltip>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Stack>
  );
}
