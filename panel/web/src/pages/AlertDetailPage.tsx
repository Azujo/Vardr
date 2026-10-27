// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import {
  Accordion,
  Alert as MAlert,
  Anchor,
  Badge,
  Box,
  Button,
  Card,
  Code,
  Group,
  Modal,
  Select,
  SimpleGrid,
  Timeline,
  Stack,
  Table,
  Text,
  Textarea,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconArrowLeft, IconMessage, IconSearch, IconUserCheck, IconArrowsExchange, IconSparkles } from "@tabler/icons-react";
import { Link, useParams } from "react-router-dom";
import {
  ago,
  alertStatusLabels,
  alertText,
  alertsApi,
  eventsApi,
  formatDate,
  incidentStatusColors,
  levelLabels,
  ruleText,
  type Alert,
  type AlertActivity,
  type AlertStatus,
  type EventDetail,
  type RuleAttack,
  type IncidentRef,
  type RuleAttribution,
  type RuleInfo,
  type Resolution,
} from "../api";
import { useTranslation } from "react-i18next";
import i18n from "../i18n";
import { useAuth } from "../auth";
import { AttackBadges, AttributionLine } from "../attack";
import { ResolutionPicker, RiskBadge, resolutionLabel } from "../risk";
import AddToIncident from "./AddToIncident";
import { AlertAnalyses, useAssistant } from "../assistant";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
        {label}
      </Text>
      <Text size="sm">{children || "—"}</Text>
    </div>
  );
}

// Zdarzenie alertu: szczegóły pobierane z Mímira po rozwinięciu.
function EventPanel({ id, time }: { id: string; time: string }) {
  const { t } = useTranslation("alerts");
  const [ev, setEv] = useState<EventDetail | null>(null);
  const [err, setErr] = useState("");
  const heartbeat = id.startsWith("heartbeat:");
  useEffect(() => {
    if (heartbeat) return;
    eventsApi
      .get(id, time)
      .then((r) => setEv(r.event))
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, [id, time, heartbeat]);
  if (heartbeat) {
    const agent = id.split(":")[1];
    return (
      <Stack gap="xs">
        <Text size="sm">{t("detail.heartbeat")}</Text>
        <Anchor component={Link} to={`/agents/${encodeURIComponent(agent)}`} size="sm">
          {t("detail.agentLink", { agent })}
        </Anchor>
      </Stack>
    );
  }
  if (err) return <Text size="sm" c="red">{err}</Text>;
  if (!ev) return <Text size="sm" c="dimmed">{t("common:loading")}</Text>;
  return (
    <Stack gap="xs">
      <Table withTableBorder verticalSpacing={2} fz="sm">
        <Table.Tbody>
          {Object.entries(ev.fields)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([k, v]) => (
              <Table.Tr key={k}>
                <Table.Td w={220} c="dimmed">
                  {k}
                </Table.Td>
                <Table.Td style={{ wordBreak: "break-all" }}>{v}</Table.Td>
              </Table.Tr>
            ))}
        </Table.Tbody>
      </Table>
      <Anchor component={Link} to={`/events?q=${encodeURIComponent(`host:${ev.host}`)}`} size="sm">
        {t("detail.hostEvents")}
      </Anchor>
    </Stack>
  );
}

// Aliasy pól jak w detektorze (Sysmon 1 / Security 4688 i nazwy Sigmy).
const aliases: Record<string, string[]> = {
  Image: ["Image", "NewProcessName"],
  ParentImage: ["ParentImage", "ParentProcessName"],
  User: ["User", "SubjectUserName"],
  ServiceFileName: ["ServiceFileName", "ImagePath"],
};

// renderInstructions: zmienne {{Pole}} z wartości zdarzenia (dla alertów
// sprzed zapisywania gotowej instrukcji); bez zdarzenia – „(brak)”.
function renderInstructions(text: string, ev: EventDetail | null): string {
  const none = i18n.t("alerts:detail.none");
  return text.replace(/\{\{\s*([A-Za-z0-9_.]+)\s*\}\}/g, (_, name: string) => {
    if (!ev) return none;
    const special: Record<string, string> = { Computer: ev.host, Hostname: ev.host, EventID: String(ev.code) };
    let v = special[name];
    for (const n of aliases[name] ?? [name]) {
      if (!v && ev.fields[n]) v = ev.fields[n];
    }
    return v && v !== "-" ? v : none;
  });
}

export default function AlertDetailPage() {
  const { id } = useParams();
  const { t } = useTranslation("alerts");
  const { t: ti } = useTranslation("incidents");
  const { user, can } = useAuth();
  const [alert, setAlert] = useState<Alert | null>(null);
  const [events, setEvents] = useState<{ event_id: string; event_time: string }[]>([]);
  const [rule, setRule] = useState<RuleInfo | undefined>();
  const [error, setError] = useState("");
  const [closing, setClosing] = useState(false);
  const [reason, setReason] = useState("");
  const [resolution, setResolution] = useState<Resolution | "">("");
  const [firstEvent, setFirstEvent] = useState<EventDetail | null>(null);
  const [activity, setActivity] = useState<AlertActivity[]>([]);
  const [related, setRelated] = useState<Alert[]>([]);
  const [attack, setAttack] = useState<Record<string, RuleAttack>>({});
  const [attribution, setAttribution] = useState<RuleAttribution | undefined>();
  const [incidents, setIncidents] = useState<IncidentRef[]>([]);
  const [toIncident, setToIncident] = useState(false);
  const [assignees, setAssignees] = useState<{ value: string; label: string }[]>([]);
  const [note, setNote] = useState("");

  const load = useCallback(() => {
    alertsApi
      .get(Number(id))
      .then((r) => {
        setAlert(r.alert);
        setEvents(r.events);
        setRule(r.rule);
        setActivity(r.activity);
        setRelated(r.related);
        setAttack(r.attack ?? {});
        setAttribution(r.attribution);
        setIncidents(r.incidents ?? []);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [id]);
  useEffect(() => load(), [load]);
  useEffect(() => {
    alertsApi
      .assignees()
      .then((r) => setAssignees(r.assignees.map((a) => ({ value: a.username, label: a.display_name || a.username }))))
      .catch(() => setAssignees([]));
  }, []);

  const fail = (e: unknown) => notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
  const assign = async (who: string) => {
    try {
      await alertsApi.assign(Number(id), who);
      load();
    } catch (e) {
      fail(e);
    }
  };
  const addNote = async () => {
    try {
      const r = await alertsApi.addNote(Number(id), note.trim());
      setActivity(r.activity);
      setNote("");
    } catch (e) {
      fail(e);
    }
  };

  // Teksty w języku konta (reguła z tłumaczeniem, alert sprzed tłumaczeń –
  // instrukcja z szablonu reguły).
  const rt = rule ? ruleText(rule) : null;
  const at = alert ? alertText(alert, rule) : null;
  // Starsze alerty nie mają gotowej instrukcji – pierwsze zdarzenie do uzupełnienia zmiennych.
  const needsRender = !!at && !at.instructions && !!rt?.instructions.includes("{{");
  useEffect(() => {
    if (!needsRender || events.length === 0) return;
    const first = events[events.length - 1];
    eventsApi
      .get(first.event_id, first.event_time)
      .then((r) => setFirstEvent(r.event))
      .catch(() => setFirstEvent(null));
  }, [needsRender, events]);

  const setStatus = async (s: AlertStatus, why?: string) => {
    try {
      await alertsApi.setStatus(Number(id), s, why, s === "closed" ? resolution : "");
      setClosing(false);
      setReason("");
      setResolution("");
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    }
  };

  if (error) return <MAlert color="red">{error}</MAlert>;
  if (!alert) return null;
  const canEdit = can("alerts", "write");
  const { open: openAssistant } = useAssistant();
  const lv = levelLabels[alert.level];
  // Zdarzenia z okolicy alertu w Mímirze: komputer, ±15 min od pierwszego i ostatniego zdarzenia.
  const around = alert.host_name
    ? `/events?${new URLSearchParams({
        q: `host:${alert.host_name}`,
        range: "custom",
        from: new Date(new Date(alert.first_seen).getTime() - 15 * 60000).toISOString(),
        to: new Date(new Date(alert.last_seen).getTime() + 15 * 60000).toISOString(),
      }).toString()}`
    : "";

  return (
    <Stack>
      <Anchor component={Link} to="/alerts" size="sm">
        <Group gap={4}>
          <IconArrowLeft size={14} /> {t("detail.back")}
        </Group>
      </Anchor>
      <Group justify="space-between" align="flex-start">
        <div>
          <Group gap="xs">
            <Badge color={lv.color} size="lg">
              {lv.label}
            </Badge>
            <Badge variant="light" color={alertStatusLabels[alert.status].color} size="lg">
              {alertStatusLabels[alert.status].label}
            </Badge>
          </Group>
          <Title order={2} mt="xs">
            {at!.title}
          </Title>
          <Text c="dimmed" size="sm">
            {t("detail.subtitle", { id: alert.id, summary: at!.summary })}
          </Text>
          <Box mt={6}>
            <AttackBadges ra={attack[alert.rule_id]} />
          </Box>
        </div>
        <Group>
          {can("ai", "use") && (
            <Button variant="light" color="violet" leftSection={<IconSparkles size={16} />} onClick={() => openAssistant({ alertId: alert.id })}>
              {i18n.t("ai:assistant.analyze")}
            </Button>
          )}
        {canEdit && (
          <Group>
            <Select
              w={190}
              placeholder={t("detail.unassigned")}
              clearable
              aria-label={t("detail.assignee")}
              leftSection={<IconUserCheck size={14} />}
              data={assignees}
              value={alert.assignee || null}
              onChange={(v) => void assign(v ?? "")}
            />
            {alert.status === "open" && (
              <Button
                onClick={async () => {
                  if (!alert.assignee && user) await assign(user.username);
                  await setStatus("acknowledged");
                }}
              >
                {t("detail.take")}
              </Button>
            )}
            {alert.status !== "closed" && (
              <Button color="gray" variant="light" onClick={() => setClosing(true)}>
                {t("close")}
              </Button>
            )}
            {alert.status === "closed" && (
              <Button variant="light" onClick={() => void setStatus("open")}>
                {t("reopen")}
              </Button>
            )}
          </Group>
        )}
        </Group>
      </Group>

      <Card withBorder>
        <SimpleGrid cols={{ base: 2, md: 4 }}>
          <Field label={t("col.host")}>
            {alert.host_name}
            {alert.host_name && <RiskBadge type="host" entity={alert.host_name} />}
          </Field>
          <Field label={t("col.user")}>
            {alert.user_identity && alert.user_identity !== alert.user_name.toLowerCase()
              ? t("detail.userPerson", { user: alert.user_name || "—", person: alert.user_identity })
              : alert.user_name}
            {(alert.user_identity || alert.user_name) && <RiskBadge type="user" entity={alert.user_identity || alert.user_name} />}
          </Field>
          <Field label={t("detail.sourceIp")}>{alert.source_ip}</Field>
          <Field label={t("detail.agent")}>{alert.agent_id}</Field>
          <Field label={t("detail.firstSeen")}>{formatDate(alert.first_seen)}</Field>
          <Field label={t("col.lastSeen")}>{formatDate(alert.last_seen)}</Field>
          <Field label={t("col.hits")}>{String(alert.hits)}</Field>
          <Field label={t("detail.engine")}>{t(`engineLong.${alert.engine}`, { defaultValue: alert.engine })}</Field>
        </SimpleGrid>
        {Object.keys(alert.group_fields).length > 0 && (
          <Text size="sm" mt="sm">
            {t("detail.key")}{" "}
            {Object.entries(alert.group_fields).map(([k, v]) => (
              <Code key={k} mr="xs">
                {k} = {v}
              </Code>
            ))}
          </Text>
        )}
        {alert.status === "closed" && (
          <Text size="sm" mt="sm" c="dimmed">
            {t("detail.closedBy", { by: alert.closed_by, date: formatDate(alert.closed_at), reason:
                alert.closed_by === "system" && i18n.resolvedLanguage !== "pl" && i18n.exists(`autoClose.${alert.rule_id}`, { ns: "alerts" })
                  ? t(`autoClose.${alert.rule_id}`)
                  : alert.close_reason,
            })}
            {alert.resolution && ` (${resolutionLabel(alert.resolution)})`}
          </Text>
        )}
      </Card>

      <Group gap="xs">
        {around && (
          <Button component={Link} to={around} variant="light" size="xs" leftSection={<IconSearch size={14} />}>
            {t("detail.around")}
          </Button>
        )}
        {alert.host_name && (
          <Button component={Link} to={`/alerts?status=all&host=${encodeURIComponent(alert.host_name)}`} variant="subtle" size="xs">
            {t("detail.allHost")}
          </Button>
        )}
        {alert.user_name && (
          <Button component={Link} to={`/alerts?status=all&user=${encodeURIComponent(alert.user_name)}`} variant="subtle" size="xs">
            {t("detail.allUser")}
          </Button>
        )}
      </Group>

      {can("ai", "use") && <AlertAnalyses alertId={alert.id} />}

      {(incidents.length > 0 || can("incidents", "write")) && (
        <Card withBorder>
          <Group justify="space-between">
            <Title order={4}>{t("detail.incidents")}</Title>
            {can("incidents", "write") && (
              <Button size="xs" variant="light" color="red" onClick={() => setToIncident(true)}>
                {t("toIncident")}
              </Button>
            )}
          </Group>
          {incidents.length === 0 ? (
            <Text size="sm" c="dimmed">
              {t("detail.noIncident")}
            </Text>
          ) : (
            incidents.map((i) => (
              <Group key={i.id} gap="xs">
                <Anchor component={Link} to={`/incidents/${i.id}`} size="sm">
                  #{i.id} {i.title}
                </Anchor>
                <Badge size="sm" variant="light" color={incidentStatusColors[i.status]}>
                  {ti(`status.${i.status}`)}
                </Badge>
              </Group>
            ))
          )}
          <AddToIncident alertIds={[alert.id]} defaultTitle={at!.title} opened={toIncident} onClose={() => setToIncident(false)} />
        </Card>
      )}

      {rule && (
        <Card withBorder>
          <Title order={4}>{t("detail.rule")}</Title>
          <AttributionLine a={attribution} />
          {rt!.description && (
            <Text size="sm" mt="xs" style={{ whiteSpace: "pre-line" }}>
              {rt!.description}
            </Text>
          )}
          {(at!.instructions || rt!.instructions) && (
            <MAlert color="blue" mt="sm" title={t("detail.whatToDo")}>
              <Text size="sm" style={{ whiteSpace: "pre-line" }}>
                {at!.instructions || renderInstructions(rt!.instructions, firstEvent)}
              </Text>
            </MAlert>
          )}
          <Group gap={4} mt="sm">
            {rule.tags.map((tag) => (
              <Badge key={tag} variant="outline" size="sm">
                {tag}
              </Badge>
            ))}
          </Group>
        </Card>
      )}

      <SimpleGrid cols={{ base: 1, lg: 2 }}>
        <Card withBorder>
          <Title order={4} mb="sm">
            {t("detail.history")}
          </Title>
          <Timeline bulletSize={22} lineWidth={2}>
            <Timeline.Item bullet={<IconArrowsExchange size={12} />} title={t("detail.created")}>
              <Text size="xs" c="dimmed">
                {formatDate(alert.created_at)} · {t("detail.engineShort", { engine: t(`engine.${alert.engine}`, { defaultValue: alert.engine }) })}
              </Text>
            </Timeline.Item>
            {activity.map((a) => (
              <Timeline.Item
                key={a.id}
                bullet={a.kind === "note" ? <IconMessage size={12} /> : a.kind === "assign" ? <IconUserCheck size={12} /> : <IconArrowsExchange size={12} />}
                title={
                  a.kind === "note"
                    ? t("detail.noteBy", { actor: a.actor })
                    : a.kind === "assign"
                      ? a.details?.to
                        ? t("detail.assigned", { actor: a.actor, to: a.details.to })
                        : t("detail.unassignedBy", { actor: a.actor })
                      : `${a.actor}: ${a.details?.to ? alertStatusLabels[a.details.to as AlertStatus]?.label ?? a.details.to : ""}`
                }
              >
                {a.text && (
                  <Text size="sm" style={{ whiteSpace: "pre-line" }}>
                    {a.text}
                  </Text>
                )}
                <Text size="xs" c="dimmed">
                  {formatDate(a.at)}
                </Text>
              </Timeline.Item>
            ))}
          </Timeline>
          {canEdit && (
            <Stack gap="xs" mt="md">
              <Textarea
                placeholder={t("detail.notePlaceholder")}
                autosize
                minRows={2}
                maxLength={4000}
                value={note}
                onChange={(e) => setNote(e.currentTarget.value)}
              />
              <Group justify="flex-end">
                <Button size="xs" disabled={!note.trim()} onClick={() => void addNote()}>
                  {t("detail.addNote")}
                </Button>
              </Group>
            </Stack>
          )}
        </Card>
        <Card withBorder>
          <Title order={4} mb="xs">
            {t("detail.related", { count: related.length })}
          </Title>
          <Text size="xs" c="dimmed" mb="xs">
            {t("detail.relatedHint")}
          </Text>
          {related.length === 0 ? (
            <Text size="sm" c="dimmed">
              {t("detail.noRelated")}
            </Text>
          ) : (
            <Table verticalSpacing={4} fz="sm" highlightOnHover>
              <Table.Tbody>
                {related.map((r) => (
                  <Table.Tr key={r.id}>
                    <Table.Td>
                      <Badge size="sm" color={levelLabels[r.level].color}>
                        {levelLabels[r.level].label}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Anchor component={Link} to={`/alerts/${r.id}`} size="sm">
                        #{r.id} {alertText(r, r.rule_id === alert.rule_id ? rule : undefined).title}
                      </Anchor>
                      <Text size="xs" c="dimmed">
                        {r.host_name}
                        {r.user_name ? ` · ${r.user_name}` : ""}
                      </Text>
                    </Table.Td>
                    <Table.Td style={{ whiteSpace: "nowrap" }} title={formatDate(r.first_seen)}>
                      {ago(r.first_seen)}
                    </Table.Td>
                    <Table.Td>
                      <Badge size="sm" variant="light" color={alertStatusLabels[r.status].color}>
                        {alertStatusLabels[r.status].label}
                      </Badge>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          )}
        </Card>
      </SimpleGrid>

      <Card withBorder>
        <Title order={4} mb="xs">
          {alert.hits > events.length
            ? t("detail.eventsOf", { count: events.length, hits: alert.hits })
            : t("detail.events", { count: events.length })}
        </Title>
        <Accordion variant="separated">
          {events.map((e) => (
            <Accordion.Item key={e.event_id} value={e.event_id}>
              <Accordion.Control>
                <Text size="sm">
                  {formatDate(e.event_time)} · <Code>{e.event_id}</Code>
                </Text>
              </Accordion.Control>
              <Accordion.Panel>
                <EventPanel id={e.event_id} time={e.event_time} />
              </Accordion.Panel>
            </Accordion.Item>
          ))}
        </Accordion>
      </Card>

      <Modal opened={closing} onClose={() => setClosing(false)} title={t("detail.closeTitle")} centered>
        <Stack>
          <ResolutionPicker value={resolution} onChange={setResolution} />
          <Textarea
            label={t("reason")}
            description={t("detail.reasonHint")}
            autosize
            minRows={2}
            value={reason}
            onChange={(e) => setReason(e.currentTarget.value)}
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setClosing(false)}>
              {t("detail.cancel")}
            </Button>
            <Button onClick={() => void setStatus("closed", reason)}>{t("detail.closeTitle")}</Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}
