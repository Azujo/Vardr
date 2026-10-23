// SPDX-License-Identifier: AGPL-3.0-or-later

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
import { agentsApi, ago, configStateLabels, enrollApi, formatDate, formatNumber, type AgentView, type AgentsSummary } from "../api";
import { useTranslation } from "react-i18next";
import i18n from "../i18n";
import { useAuth } from "../auth";

type Filter = "all" | "online" | "offline" | "problems" | "retired";

// Odstęp czasu w sekundach: „12 min”, „5 h”, „3 dni”.
function span(s: number): string {
  if (s < 3600) return i18n.t("agents:span.min", { n: Math.floor(s / 60) });
  if (s < 172800) return i18n.t("agents:span.h", { n: Math.floor(s / 3600) });
  return i18n.t("agents:span.d", { count: Math.floor(s / 86400) });
}

// Problemy agenta w języku użytkownika (serwer podaje kody; starszy serwer –
// tylko polskie opisy).
export function agentProblems(a: AgentView): string[] {
  if (!a.issues) return a.problems;
  return a.issues.map((p, i) => {
    const x = p.args ?? {};
    const key = `agents:issue.${p.code}`;
    if (!i18n.exists(key)) return a.problems[i] ?? p.code;
    const extra: Record<string, string> = {};
    if (typeof x.s === "number") extra.span = span(x.s);
    if (typeof x.how === "string") extra.how = i18n.t(`agents:stopHow.${x.how}`, { defaultValue: x.how });
    if (typeof x.state === "string") extra.state = i18n.t(`agents:channel.${x.state}`, { defaultValue: x.state });
    if (typeof x.bytes === "number") extra.mb = (x.bytes / 1048576).toFixed(1);
    if (p.code === "protection_down") extra.error = x.error ? `: ${x.error}` : "";
    if (p.code === "clock") extra.dir = i18n.t(x.ahead ? "agents:clockAhead" : "agents:clockBehind");
    return i18n.t(key, { ...x, ...extra, count: typeof x.n === "number" ? x.n : typeof x.days === "number" ? x.days : undefined });
  });
}

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
  const { t } = useTranslation("agents");
  if (a.state === "retired")
    return (
      <Tooltip label={t("state.retiredTip")}>
        <Badge color="dark" variant="light">
          {t("state.retired")}
        </Badge>
      </Tooltip>
    );
  if (a.state === "offline") {
    if (a.stopping === "stop") return <Badge color="red">{t("state.stoppedNoToken")}</Badge>;
    if (a.stopping && a.stopping !== "shutdown") return <Badge color="gray">{t("state.stopped")}</Badge>;
    return <Badge color="gray">offline</Badge>;
  }
  if (a.tamper_24h) return <Badge color="red">{t("state.tamper")}</Badge>;
  if (a.problems.length > 0) return <Badge color="orange">{t("state.problems")}</Badge>;
  return <Badge color="green">online</Badge>;
}

export default function AgentsPage() {
  const { t } = useTranslation("agents");
  const { user, can } = useAuth();
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
      // Wycofani (certyfikat unieważniony) – tylko w osobnym filtrze.
      if ((filter === "retired") !== (a.state === "retired")) return false;
      if (filter === "online" && a.state !== "online") return false;
      if (filter === "offline" && a.state !== "offline") return false;
      if (filter === "problems" && a.problems.length === 0) return false;
      return !q || [a.id, a.hostname, a.remote_ip, a.version, a.os, a.group].some((v) => v.toLowerCase().includes(q));
    });
  }, [agents, query, filter]);

  const [orphans, setOrphans] = useState<{ serial: string; agent_id: string; hostname: string; not_after: string }[]>([]);
  const loadOrphans = () => {
    if (!can("agents", "write")) return;
    agentsApi
      .orphanCerts()
      .then((r) => setOrphans(r.certs))
      .catch(() => setOrphans([]));
  };
  useEffect(loadOrphans, [user]);
  const revokeOrphan = async (id: string) => {
    const reason = window.prompt(t("orphans.prompt", { id }), t("orphans.defaultReason"));
    if (reason === null) return;
    try {
      const r = await enrollApi.revokeAgent(id, reason);
      notifications.show({ color: "green", message: t("orphans.revoked", { n: r.revoked }) });
      loadOrphans();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    }
  };

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
          <Title order={2}>{t("title")}</Title>
          <Text c="dimmed" size="sm">
            {t("intro")}
          </Text>
        </div>
        {can("agents", "write") && (
          <Tooltip
            multiline
            w={360}
            label={t("updateTip")}
          >
            <Button variant="light" leftSection={<IconDownload size={16} />} loading={downloading} onClick={() => void updateMSI()}>
              {t("update")}
            </Button>
          </Tooltip>
        )}
      </Group>
      {error && <Alert color="red">{error}</Alert>}
      {orphans.length > 0 && (
        <Alert color="red" title={t("orphans.title", { count: orphans.length })}>
          <Text size="sm" mb="xs">
            {t("orphans.text")}
          </Text>
          <Table fz="sm" verticalSpacing={4}>
            <Table.Tbody>
              {[...new Set(orphans.map((c) => c.agent_id))].map((id) => {
                const cs = orphans.filter((c) => c.agent_id === id);
                return (
                  <Table.Tr key={id}>
                    <Table.Td>
                      <Text size="sm" fw={500}>
                        {cs[0].hostname || id}
                      </Text>
                      <Text size="xs" c="dimmed">
                        {t("orphans.line", { id, n: cs.length, date: formatDate(cs[cs.length - 1].not_after) })}
                      </Text>
                    </Table.Td>
                    <Table.Td ta="right">
                      <Button size="xs" color="red" variant="light" onClick={() => void revokeOrphan(id)}>
                        {t("revoke")}
                      </Button>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Alert>
      )}

      {summary && (
        <SimpleGrid cols={{ base: 2, md: 4 }}>
          <StatCard label={t("stat.total")} value={summary.total} color="indigo" icon={<IconServer size={28} opacity={0.5} />} />
          <StatCard label="Online" value={summary.online} color="green" icon={<IconCircleCheck size={28} opacity={0.5} />} />
          <StatCard
            label="Offline"
            value={summary.offline}
            color={summary.offline ? "gray" : "dimmed"}
            icon={<IconPlugConnectedX size={28} opacity={0.5} />}
          />
          <StatCard
            label={t("stat.problems")}
            value={summary.with_problems}
            color={summary.with_problems ? "orange" : "dimmed"}
            icon={<IconAlertTriangle size={28} opacity={0.5} />}
          />
        </SimpleGrid>
      )}

      <Group justify="space-between" wrap="wrap">
        <TextInput
          placeholder={t("search")}
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
            { value: "all", label: t("filter.all") },
            { value: "online", label: "Online" },
            { value: "offline", label: "Offline" },
            { value: "problems", label: t("filter.problems") },
            ...(summary?.retired ? [{ value: "retired", label: t("filter.retired", { n: summary.retired }) }] : []),
          ]}
        />
      </Group>

      {agents.length === 0 && !error ? (
        <Alert color="blue" title={t("empty.title")}>
          {t("empty.text")}
        </Alert>
      ) : (
        <Table.ScrollContainer minWidth={900}>
          <Table striped highlightOnHover verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("col.state")}</Table.Th>
                <Table.Th>{t("col.agent")}</Table.Th>
                <Table.Th>{t("col.ip")}</Table.Th>
                <Table.Th>{t("col.group")}</Table.Th>
                <Table.Th>{t("col.version")}</Table.Th>
                <Table.Th>{t("col.lastSeen")}</Table.Th>
                <Table.Th>{t("col.events")}</Table.Th>
                <Table.Th>{t("col.channels")}</Table.Th>
                <Table.Th>{t("col.problems")}</Table.Th>
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
                        {t("config", { state: configStateLabels[a.config_state]?.label })}
                      </Badge>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td>{a.version || "—"}</Table.Td>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>
                    <Tooltip label={formatDate(a.last_seen)}>
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
                      <Tooltip label={agentProblems(a).join("\n")} multiline maw={400} style={{ whiteSpace: "pre-line" }}>
                        <Text size="sm" c="orange" lineClamp={2}>
                          {agentProblems(a).join("; ")}
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
