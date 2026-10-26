// SPDX-License-Identifier: AGPL-3.0-or-later

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
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth";
import { StateBadge, agentProblems } from "./AgentsPage";
import { AgentProtection } from "./AgentProtection";
import { RiskBadge } from "../risk";

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

const channelColors: Record<string, string> = { ok: "green", starting: "blue", not_found: "gray", access_denied: "red", error: "red" };

function duration(ns?: number): string {
  if (!ns) return "—";
  const s = ns / 1e9;
  if (s < 1) return `${Math.round(s * 1000)} ms`;
  if (s < 120) return `${s.toFixed(1)} s`;
  if (s < 7200) return `${Math.round(s / 60)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

export default function AgentDetailPage() {
  const { t } = useTranslation("agents");
  const { id = "" } = useParams();
  const { can } = useAuth();
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
      notifications.show({ color: "green", message: t("detail.groupChanged") });
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
    if (
      !window.confirm(t("detail.removeConfirm", { id }))
    )
      return;
    try {
      await agentsApi.remove(id);
      notifications.show({ color: "green", message: t("detail.removed", { id }) });
      navigate("/agents");
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    }
  };

  const revokeCert = async () => {
    const reason = window.prompt(t("detail.revokePrompt", { id }), t("detail.revokeDefault"));
    if (reason === null) return;
    try {
      const r = await enrollApi.revokeAgent(id, reason);
      notifications.show({
        color: r.revoked ? "green" : "yellow",
        message: r.revoked ? t("detail.revoked", { n: r.revoked }) : t("detail.noCerts"),
      });
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    }
  };

  const back = (
    <Anchor component={Link} to="/agents" size="sm">
      <Group gap={4}>
        <IconArrowLeft size={14} /> {t("detail.back")}
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
            {agent.hostname && <RiskBadge type="host" entity={agent.hostname} />}
          </Group>
          <Text c="dimmed" size="sm">
            {agent.id} · {agent.os || t("detail.unknownOs")} · {t("detail.agentVersion", { v: agent.version || "?" })}
          </Text>
        </div>
        {can("agents", "write") && (
          <Group gap="xs">
            <Button variant="light" color="red" leftSection={<IconCertificateOff size={16} />} onClick={() => void revokeCert()}>
              {t("detail.revokeCert")}
            </Button>
            <Button variant="default" leftSection={<IconTrash size={16} />} onClick={() => void remove()}>
              {t("detail.remove")}
            </Button>
          </Group>
        )}
      </Group>

      {agent.problems.length > 0 && (
        <Alert color="orange" title={t("detail.attention")}>
          <List size="sm">
            {agentProblems(agent).map((pr) => (
              <List.Item key={pr}>{pr}</List.Item>
            ))}
          </List>
        </Alert>
      )}

      <Card withBorder>
        <Group justify="space-between" align="flex-start" wrap="wrap">
          <div>
            <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
              {t("detail.config")}
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
              {t("detail.configExpected", { v: agent.config_expected })}
              {agent.config_applied ? ` · ${t("detail.configApplied", { v: agent.config_applied })}` : ""}
            </Text>
          </div>
          {can("agents", "write") ? (
            <Select
              label={t("col.group")}
              w={240}
              data={groups.map((g) => ({ value: String(g.id), label: g.name }))}
              value={String(agent.group_id)}
              allowDeselect={false}
              onChange={(v) => v && Number(v) !== agent.group_id && void changeGroup(Number(v))}
            />
          ) : (
            <Text size="sm">{t("detail.groupIs", { group: agent.group })}</Text>
          )}
        </Group>
      </Card>

      <Card withBorder>
        <SimpleGrid cols={{ base: 2, md: 4 }} spacing="lg">
          <Field label={t("col.lastSeen")}>
            {ago(agent.last_seen)} <Text span size="xs" c="dimmed">({formatDate(agent.last_seen)})</Text>
          </Field>
          <Field label={t("col.ip")}>{agent.remote_ip || "—"}</Field>
          <Field label={t("detail.runningSince")}>{agent.started_at ? `${formatDate(agent.started_at)} (${ago(agent.started_at)})` : "—"}</Field>
          <Field label={t("detail.firstSeen")}>{formatDate(agent.first_seen)}</Field>
          <Field label={t("detail.sending")}>
            {status.server?.healthy ? (
              <Badge color="green" variant="light">{t("detail.works")}</Badge>
            ) : (
              <Badge color="red" variant="light">{t("detail.error")}</Badge>
            )}
          </Field>
          <Field label={t("detail.lastBatch")}>{ago(status.server?.last_accepted_at)}</Field>
          <Field label={t("detail.certValid")}>
            {agent.cert_not_after ? `${formatDate(agent.cert_not_after)} (${t("detail.days", { count: agent.cert_days_left ?? 0 })})` : "—"}
          </Field>
          <Field label={t("detail.lastError")}>
            {status.server?.last_error ? `${status.server.last_error} (${ago(status.server.last_error_at)})` : "—"}
          </Field>
        </SimpleGrid>
      </Card>

      <AgentProtection agent={agent} status={status} admin={can("agents", "write")} />

      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Card withBorder>
          <Title order={4} mb="sm">
            {t("detail.counters")}
          </Title>
          <SimpleGrid cols={3} spacing="md">
            <Field label={t("detail.read")}>{formatNumber(c.read)}</Field>
            <Field label={t("detail.accepted")}>{formatNumber(c.accepted)}</Field>
            <Field label={t("detail.filtered")}>{formatNumber(c.filtered)}</Field>
            <Field label={t("detail.retries")}>{formatNumber(c.retries)}</Field>
            <Field label={t("detail.truncated")}>{formatNumber(c.truncated)}</Field>
            <Field label={t("detail.quarantined")}>{formatNumber(c.quarantined)}</Field>
          </SimpleGrid>
        </Card>
        <Card withBorder>
          <Title order={4} mb="sm">
            {t("detail.resources")}
          </Title>
          <SimpleGrid cols={3} spacing="md">
            <Field label={t("detail.cpu")}>{duration(p.cpu_time_ns)}</Field>
            <Field label={t("detail.heap")}>{p.heap_mb !== undefined ? `${p.heap_mb.toFixed(1)} MB` : "—"}</Field>
            <Field label={t("detail.sys")}>{p.sys_mb !== undefined ? `${p.sys_mb.toFixed(1)} MB` : "—"}</Field>
            <Field label={t("detail.throttleEps")}>{duration(status.throttle?.eps_ns)}</Field>
            <Field label={t("detail.throttleBw")}>{duration(status.throttle?.bandwidth_ns)}</Field>
            <Field label={t("detail.goroutines")}>{p.goroutines ?? "—"}</Field>
          </SimpleGrid>
        </Card>
      </SimpleGrid>

      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Card withBorder>
          <Title order={4} mb="sm">
            {t("detail.buffer")}
          </Title>
          {!status.buffer ? (
            <Text size="sm" c="dimmed">
              {t("detail.bufferOld")}
            </Text>
          ) : status.buffer.disabled ? (
            <Text size="sm">{t("detail.bufferOff")}</Text>
          ) : (
            <SimpleGrid cols={3} spacing="md">
              <Field label={t("detail.inBuffer")}>
                {t("detail.bufferContent", { batches: status.buffer.batches, mb: (status.buffer.bytes / 1048576).toFixed(1) })}
              </Field>
              <Field label={t("detail.limit")}>{Math.round(status.buffer.max_bytes / 1048576)} MB</Field>
              <Field label={t("detail.onFull")}>{status.buffer.on_full === "drop_oldest" ? t("detail.dropOldest") : t("detail.pause")}</Field>
              <Field label={t("detail.oldest")}>{status.buffer.oldest_at ? ago(status.buffer.oldest_at) : "—"}</Field>
              <Field label={t("detail.spooled")}>{t("detail.events", { n: formatNumber(status.buffer.spooled_events) })}</Field>
              <Field label={t("detail.dropped")}>
                {status.buffer.dropped_events > 0 ? (
                  <Text c="red" size="sm">
                    {t("detail.events", { n: formatNumber(status.buffer.dropped_events) })}
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
            {t("detail.clockSysmon")}
          </Title>
          {!status.clock?.measured_at && !status.clock?.time_service ? (
            <Text size="sm" c="dimmed">
              {t("detail.clockOld")}
            </Text>
          ) : (
            <SimpleGrid cols={3} spacing="md">
              <Field label={t("detail.offset")}>
                {status.clock?.measured_at
                  ? `${status.clock.offset_ms > 0 ? "+" : ""}${(status.clock.offset_ms / 1000).toFixed(1)} s (±${status.clock.uncertainty_ms} ms)`
                  : "—"}
              </Field>
              <Field label={t("detail.measured")}>{ago(status.clock?.measured_at)}</Field>
              <Field label="Sysmon">
                {!status.sysmon ? (
                  "—"
                ) : !status.sysmon.installed ? (
                  <Badge color={agent.sysmon_required ? "red" : "gray"} variant="light">{t("detail.none")}</Badge>
                ) : (
                  <Badge color={status.sysmon.running ? "green" : "red"} variant="light">
                    {status.sysmon.running ? t("detail.works") : t("detail.stopped")} {status.sysmon.version}
                  </Badge>
                )}
              </Field>
              <Field label={t("detail.sysmonConfig")}>
                <Text size="sm" ff="monospace">
                  {status.sysmon?.config_hash || "—"}
                </Text>
              </Field>
              <Field label={t("detail.timeService")}>
                {status.clock?.time_service === "running" ? (
                  <Badge color="green" variant="light">{t("detail.works")}</Badge>
                ) : status.clock?.time_service === "stopped" ? (
                  <Badge color="gray" variant="light">{t("detail.onDemand")}</Badge>
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
          {t("col.channels")}
        </Title>
        <Table.ScrollContainer minWidth={640}>
          <Table verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("detail.channel")}</Table.Th>
                <Table.Th>{t("col.state")}</Table.Th>
                <Table.Th>{t("detail.lastRecord")}</Table.Th>
                <Table.Th>{t("detail.readAt")}</Table.Th>
                <Table.Th>{t("detail.lag")}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {(status.channels ?? []).map((ch) => {
                const s = { label: t(`channel.${ch.state}`, { defaultValue: ch.state }), color: channelColors[ch.state] ?? "gray" };
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
          {t("detail.warnings")}
        </Title>
        {(status.warnings ?? []).length === 0 ? (
          <Text size="sm" c="dimmed">
            {t("detail.noWarnings")}
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
          {raw ? t("detail.hideRaw") : t("detail.showRaw")}
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
