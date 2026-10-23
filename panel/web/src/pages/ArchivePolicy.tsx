// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Group,
  List,
  Modal,
  MultiSelect,
  NumberInput,
  PasswordInput,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  TagsInput,
  Text,
  Textarea,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAlertTriangle, IconLock, IconSettings } from "@tabler/icons-react";
import {
  agentsApi,
  ApiError,
  archiveApi,
  formatDate,
  formatDuration,
  groupLabel,
  groupsApi,
  policyStatusLabels,
  unarchivedReasonLabels,
  weakeningLabels,
  type AgentGroup,
  type AgentView,
  type ArchivePolicy as Policy,
  type PolicyChange,
  type PolicyInfo,
  type Weakening,
} from "../api";
import { useTranslation } from "react-i18next";
import i18n from "../i18n";

// Te same reguły co w serwerze (urd.Weakening) – tylko do podpowiedzi
// w formularzu; rozstrzyga serwer.
function weakening(cur: Policy, next: { enabled: boolean; retention_days: number; excluded_groups: number[]; excluded_agents: string[] }) {
  const w: Weakening[] = [];
  if (cur.enabled && !next.enabled) w.push("disable");
  if (next.retention_days < cur.retention_days) w.push("retention");
  if (next.excluded_groups.some((g) => !cur.excluded_groups.includes(g))) w.push("groups");
  if (next.excluded_agents.some((a) => !cur.excluded_agents.includes(a))) w.push("agents");
  return w;
}

function until(iso?: string) {
  if (!iso) return "";
  const s = Math.max(0, Math.round((new Date(iso).getTime() - Date.now()) / 1000));
  return s === 0 ? i18n.t("archive:policy.soon") : i18n.t("archive:policy.in", { d: formatDuration(s) });
}

function sources(c: { excluded_groups: number[]; excluded_agents: string[] }, groupName: (id: number) => string) {
  const parts = [...c.excluded_groups.map(groupName), ...c.excluded_agents];
  return parts.length ? parts.join(", ") : "—";
}

// Polityka archiwum: włączenie, retencja i źródła objęte archiwum. Zmianę
// rozpatruje archiwizator – wzmocnienie od razu, osłabienie po karencji
// i tylko po ponownym podaniu hasła.
export default function ArchivePolicy({ admin, onChanged }: { admin: boolean; onChanged: () => void }) {
  const { t } = useTranslation("archive");
  const [info, setInfo] = useState<PolicyInfo | null>(null);
  const [groups, setGroups] = useState<AgentGroup[]>([]);
  const [agents, setAgents] = useState<AgentView[]>([]);
  const [error, setError] = useState("");

  const [enabled, setEnabled] = useState(true);
  const [days, setDays] = useState<number | string>(30);
  const [exGroups, setExGroups] = useState<string[]>([]);
  const [exAgents, setExAgents] = useState<string[]>([]);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<Weakening[] | null>(null);
  const [password, setPassword] = useState("");

  const reset = useCallback((p: Policy | null) => {
    if (!p) return;
    setEnabled(p.enabled);
    setDays(p.retention_days);
    setExGroups(p.excluded_groups.map(String));
    setExAgents(p.excluded_agents);
  }, []);

  const load = useCallback(
    (resetForm: boolean) => {
      archiveApi
        .policy()
        .then((r) => {
          setInfo(r);
          setError("");
          if (resetForm) reset(r.policy);
        })
        .catch((e) => setError(e instanceof Error ? e.message : String(e)));
    },
    [reset],
  );
  useEffect(() => {
    load(true);
    groupsApi
      .list()
      .then((r) => setGroups(r.groups))
      .catch(() => {});
    agentsApi
      .list()
      .then((r) => setAgents(r.agents))
      .catch(() => {});
    const t = setInterval(() => load(false), 15000);
    return () => clearInterval(t);
  }, [load]);

  const groupName = useCallback(
    (id: number) => groups.find((g) => g.id === id)?.name ?? t("policy.deletedGroup", { id }),
    [groups, t],
  );
  const target = useMemo(
    () => ({
      enabled,
      retention_days: Number(days) || 0,
      excluded_groups: exGroups.map(Number),
      excluded_agents: exAgents,
    }),
    [enabled, days, exGroups, exAgents],
  );
  const pol = info?.policy ?? null;
  const b = info?.bounds;
  const weak = pol ? weakening(pol, target) : [];
  const dirty =
    !!pol &&
    (pol.enabled !== target.enabled ||
      pol.retention_days !== target.retention_days ||
      [...pol.excluded_groups].sort().join() !== [...target.excluded_groups].sort().join() ||
      [...pol.excluded_agents].sort().join() !== [...target.excluded_agents].sort().join());

  const send = async (pw?: string) => {
    setBusy(true);
    try {
      const r = await archiveApi.changePolicy({ ...target, reason, password: pw });
      notifications.show({
        color: r.weakening.length ? "orange" : "green",
        message: r.weakening.length ? t("policy.scheduledMsg") : t("policy.appliedMsg"),
        autoClose: 8000,
      });
      setConfirm(null);
      setPassword("");
      setReason("");
      load(false);
      onChanged();
    } catch (e) {
      if (e instanceof ApiError && e.code === "reauth_required") {
        setConfirm(weak.length ? weak : ["disable"]);
      } else {
        notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
      }
    } finally {
      setBusy(false);
    }
  };

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (weak.length) setConfirm(weak);
    else void send();
  };

  const cancel = async (c: PolicyChange) => {
    try {
      await archiveApi.cancelChange(c.id);
      notifications.show({ color: "green", message: t("policy.cancelledMsg") });
      load(false);
      onChanged();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    }
  };

  if (error) return <Alert color="red">{error}</Alert>;
  if (!info) return null;
  if (!pol)
    return (
      <Alert color="gray">{t("policy.none")}</Alert>
    );

  const sc = info.scheduled_change;
  const groupOptions = groups.map((g) => ({ value: String(g.id), label: t("groupOption", { name: g.name, n: g.agents }) }));
  for (const id of pol.excluded_groups)
    if (!groups.some((g) => g.id === id)) groupOptions.push({ value: String(id), label: groupName(id) });

  return (
    <Stack>
      {sc && (
        <Alert color="orange" icon={<IconAlertTriangle />} title={t("policy.scheduledTitle", { when: until(sc.effective_at) })}>
          <Text size="sm">
            {t("policy.scheduledText", {
              by: sc.requested_by,
              date: formatDate(sc.requested_at),
              what: sc.weakening.map((w) => weakeningLabels[w]).join(", "),
              reason: sc.reason,
              due: formatDate(sc.effective_at),
            })}
          </Text>
          <Text size="sm" mt={4}>
            {t("policy.target", {
              state: sc.enabled ? t("policy.on") : t("policy.OFF"),
              days: sc.retention_days,
              sources: sources(sc, groupName),
            })}
          </Text>
          {admin && (
            <Button mt="sm" size="xs" color="orange" variant="light" onClick={() => void cancel(sc)}>
              {t("policy.cancelThis")}
            </Button>
          )}
        </Alert>
      )}

      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Card withBorder>
          <Stack gap={6}>
            <Title order={4}>{t("policy.current")}</Title>
            <Group gap="xs">
              <Text size="sm">{t("policy.archivingNew")}</Text>
              <Badge color={pol.enabled ? "green" : "red"} variant="light">
                {pol.enabled ? t("policy.on") : t("policy.off")}
              </Badge>
            </Group>
            <Text size="sm">
              {t("stat.retention")}: <b>{t("days", { n: pol.retention_days })}</b>
            </Text>
            <Text size="sm">{t("policy.exGroups", { list: pol.excluded_groups.length ? pol.excluded_groups.map(groupName).join(", ") : "—" })}</Text>
            <Text size="sm">{t("policy.exAgents", { list: pol.excluded_agents.length ? pol.excluded_agents.join(", ") : "—" })}</Text>
            <Text size="xs" c="dimmed">
              {t("policy.lastChange", { by: pol.updated_by, date: formatDate(pol.updated_at) })}
            </Text>
          </Stack>
        </Card>
        <Card withBorder>
          <Stack gap={6}>
            <Title order={4}>{t("policy.bounds")}</Title>
            <Text size="sm">{t("policy.retentionRange", { min: b?.min_retention_days, max: b?.max_retention_days })}</Text>
            <Text size="sm">{t("policy.grace", { d: b?.grace_s ? formatDuration(b.grace_s) : t("policy.none2") })}</Text>
            <Text size="sm">{t("policy.prefixes", { list: b?.exclude_prefixes.length ? b.exclude_prefixes.join(", ") : "—" })}</Text>
            <Text size="xs" c="dimmed">
              {t("policy.boundsHint")}
            </Text>
          </Stack>
        </Card>
      </SimpleGrid>

      {admin && (
        <Card withBorder>
          <form onSubmit={submit}>
            <Stack gap="sm">
              <Group gap="xs">
                <IconSettings size={20} />
                <Title order={4}>{t("policy.change")}</Title>
              </Group>
              <Text size="sm" c="dimmed">
                {t("policy.changeIntro", { grace: b?.grace_s ? formatDuration(b.grace_s) : t("policy.none2") })}
              </Text>
              <Switch
                label={t("policy.archiveNew")}
                checked={enabled}
                onChange={(e) => setEnabled(e.currentTarget.checked)}
              />
              <NumberInput
                label={t("policy.retentionDays")}
                description={t("policy.retentionHint", { min: b?.min_retention_days, max: b?.max_retention_days })}
                min={b?.min_retention_days}
                max={b?.max_retention_days}
                value={days}
                onChange={setDays}
                maw={240}
                required
              />
              <MultiSelect
                label={t("policy.exGroupsLabel")}
                description={t("policy.exGroupsHint")}
                data={groupOptions}
                value={exGroups}
                onChange={setExGroups}
                searchable
                clearable
              />
              <TagsInput
                label={t("policy.exAgentsLabel")}
                description={t("policy.exAgentsHint")}
                data={agents.map((a) => ({ value: a.id, label: `${a.id} (${a.hostname})` }))}
                value={exAgents}
                onChange={setExAgents}
                clearable
              />
              <Textarea
                label={t("policy.reason")}
                description={t("policy.reasonHint")}
                required
                minLength={5}
                maxLength={1000}
                autosize
                minRows={2}
                value={reason}
                onChange={(e) => setReason(e.currentTarget.value)}
              />
              {weak.length > 0 && dirty && (
                <Alert color="orange" variant="light" icon={<IconLock />}>
                  {t("policy.weakens", { what: weak.map((w) => weakeningLabels[w]).join(", ") })}
                </Alert>
              )}
              <Group>
                <Button type="submit" loading={busy} disabled={!dirty} color={weak.length ? "orange" : undefined}>
                  {t("policy.submit")}
                </Button>
                <Button variant="subtle" onClick={() => reset(pol)} disabled={!dirty}>
                  {t("policy.resetForm")}
                </Button>
              </Group>
            </Stack>
          </form>
        </Card>
      )}

      <Card withBorder>
        <Stack gap="xs">
          <Title order={4}>
            {t("policy.unarchived", { n: info.unarchived.length, total: info.agents_total ?? 0 })}
          </Title>
          {info.unarchived.length === 0 ? (
            <Text size="sm" c="dimmed">
              {t("policy.allArchived")}
            </Text>
          ) : (
            <Table.ScrollContainer minWidth={600}>
              <Table striped verticalSpacing={4}>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t("col.agent")}</Table.Th>
                    <Table.Th>{t("col.host")}</Table.Th>
                    <Table.Th>{t("col.group")}</Table.Th>
                    <Table.Th>{t("col.reason")}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {info.unarchived.slice(0, 200).map((u) => (
                    <Table.Tr key={u.agent_id}>
                      <Table.Td>{u.agent_id}</Table.Td>
                      <Table.Td>{u.hostname}</Table.Td>
                      <Table.Td>{groupLabel(u.group)}</Table.Td>
                      <Table.Td>
                        {unarchivedReasonLabels[u.reason]}
                        {u.effective_at && ` – ${t("stat.since", { date: formatDate(u.effective_at) })}`}
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )}
          {info.unarchived.length > 200 && (
            <Text size="xs" c="dimmed">
              {t("policy.first200")}
            </Text>
          )}
        </Stack>
      </Card>

      {info.changes.length > 0 && (
        <Stack gap="xs">
          <Title order={4}>{t("policy.history")}</Title>
          <Table.ScrollContainer minWidth={900}>
            <Table striped verticalSpacing="xs">
              <Table.Thead>
                <Table.Tr style={{ whiteSpace: "nowrap" }}>
                  <Table.Th>{t("manifest.no")}</Table.Th>
                  <Table.Th>{t("col.requested")}</Table.Th>
                  <Table.Th>{t("col.byReason")}</Table.Th>
                  <Table.Th>{t("policy.targetCol")}</Table.Th>
                  <Table.Th>{t("policy.weakening")}</Table.Th>
                  <Table.Th>{t("col.state")}</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {info.changes.map((c) => (
                  <Table.Tr key={c.id}>
                    <Table.Td>{c.id}</Table.Td>
                    <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(c.requested_at)}</Table.Td>
                    <Table.Td maw={260}>
                      <Group gap={4}>
                        <Text size="sm">{c.requested_by}</Text>
                        {c.reauth && (
                          <Tooltip label={t("policy.reauth")}>
                            <IconLock size={14} />
                          </Tooltip>
                        )}
                      </Group>
                      <Text size="xs" c="dimmed" lineClamp={2} title={c.reason}>
                        {c.reason}
                      </Text>
                    </Table.Td>
                    <Table.Td maw={300}>
                      <Text size="sm">
                        {c.enabled ? t("policy.onN") : t("policy.OFFN")}, {t("days", { n: c.retention_days })}
                      </Text>
                      <Text size="xs" c="dimmed" lineClamp={2}>
                        {t("policy.without", { list: sources(c, groupName) })}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      {c.weakening.length ? (
                        <Text size="sm" c="orange">
                          {c.weakening.map((w) => weakeningLabels[w]).join(", ")}
                        </Text>
                      ) : (
                        <Text size="sm" c="dimmed">
                          —
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Tooltip
                        label={
                          c.error ||
                          (c.status === "scheduled"
                            ? t("policy.tipScheduled", { date: formatDate(c.effective_at) })
                            : c.status === "cancelled"
                              ? t("policy.tipCancelled", { by: c.cancelled_by, date: formatDate(c.cancelled_at) })
                              : c.applied_at
                                ? t("policy.tipApplied", { date: formatDate(c.applied_at) })
                                : t("policy.tipPending"))
                        }
                        multiline
                        maw={400}
                      >
                        <Badge color={policyStatusLabels[c.status].color} variant="light">
                          {c.cancelled_at && (c.status === "pending" || c.status === "scheduled")
                            ? t("policy.cancelling")
                            : policyStatusLabels[c.status].label}
                        </Badge>
                      </Tooltip>
                    </Table.Td>
                    <Table.Td>
                      {admin && (c.status === "pending" || c.status === "scheduled") && !c.cancelled_at && (
                        <Button size="compact-xs" variant="subtle" color="gray" onClick={() => void cancel(c)}>
                          {t("policy.cancel")}
                        </Button>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Stack>
      )}

      <Modal opened={!!confirm} onClose={() => setConfirm(null)} title={t("policy.confirmTitle")} centered>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void send(password);
          }}
        >
          <Stack gap="sm">
            <Text size="sm">{t("policy.includes")}</Text>
            <List size="sm">
              {(confirm ?? []).map((w) => (
                <List.Item key={w}>{weakeningLabels[w]}</List.Item>
              ))}
            </List>
            <Text size="sm">
              {t("policy.confirmText", { grace: b?.grace_s ? formatDuration(b.grace_s) : t("policy.immediately") })}
            </Text>
            <PasswordInput
              label={t("yourPassword")}
              required
              autoFocus
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
            />
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setConfirm(null)}>
                {t("back")}
              </Button>
              <Button type="submit" color="orange" loading={busy}>
                {t("policy.confirm")}
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Stack>
  );
}
