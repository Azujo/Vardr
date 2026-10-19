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
import { IconArrowLeft, IconMessage, IconSearch, IconUserCheck, IconArrowsExchange } from "@tabler/icons-react";
import { Link, useParams } from "react-router-dom";
import {
  ago,
  alertStatusLabels,
  alertsApi,
  eventsApi,
  formatDate,
  levelLabels,
  type Alert,
  type AlertActivity,
  type AlertStatus,
  type EventDetail,
  type RuleAttack,
  type RuleAttribution,
  type RuleInfo,
} from "../api";
import { useAuth } from "../auth";
import { AttackBadges, AttributionLine } from "../attack";

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
        <Text size="sm">Ostatni heartbeat agenta przed przerwą – zdarzenie systemowe (nie ma go w Mímirze).</Text>
        <Anchor component={Link} to={`/agents/${encodeURIComponent(agent)}`} size="sm">
          Agent {agent} w Huginnie →
        </Anchor>
      </Stack>
    );
  }
  if (err) return <Text size="sm" c="red">{err}</Text>;
  if (!ev) return <Text size="sm" c="dimmed">wczytywanie…</Text>;
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
        Zdarzenia z tego komputera w Mímirze →
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
  return text.replace(/\{\{\s*([A-Za-z0-9_.]+)\s*\}\}/g, (_, name: string) => {
    if (!ev) return "(brak)";
    const special: Record<string, string> = { Computer: ev.host, Hostname: ev.host, EventID: String(ev.code) };
    let v = special[name];
    for (const n of aliases[name] ?? [name]) {
      if (!v && ev.fields[n]) v = ev.fields[n];
    }
    return v && v !== "-" ? v : "(brak)";
  });
}

export default function AlertDetailPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const [alert, setAlert] = useState<Alert | null>(null);
  const [events, setEvents] = useState<{ event_id: string; event_time: string }[]>([]);
  const [rule, setRule] = useState<RuleInfo | undefined>();
  const [error, setError] = useState("");
  const [closing, setClosing] = useState(false);
  const [reason, setReason] = useState("");
  const [firstEvent, setFirstEvent] = useState<EventDetail | null>(null);
  const [activity, setActivity] = useState<AlertActivity[]>([]);
  const [related, setRelated] = useState<Alert[]>([]);
  const [attack, setAttack] = useState<Record<string, RuleAttack>>({});
  const [attribution, setAttribution] = useState<RuleAttribution | undefined>();
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

  // Starsze alerty nie mają gotowej instrukcji – pierwsze zdarzenie do uzupełnienia zmiennych.
  const needsRender = !!alert && !alert.instructions && !!rule?.instructions?.includes("{{");
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
      await alertsApi.setStatus(Number(id), s, why);
      setClosing(false);
      setReason("");
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    }
  };

  if (error) return <MAlert color="red">{error}</MAlert>;
  if (!alert) return null;
  const canEdit = user?.role === "admin" || user?.role === "analyst";
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
          <IconArrowLeft size={14} /> alerty
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
            {alert.rule_title}
          </Title>
          <Text c="dimmed" size="sm">
            Alert #{alert.id} · {alert.summary}
          </Text>
          <Box mt={6}>
            <AttackBadges ra={attack[alert.rule_id]} />
          </Box>
        </div>
        {canEdit && (
          <Group>
            <Select
              w={190}
              placeholder="nieprzypisany"
              clearable
              aria-label="przypisany analityk"
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
                Biorę do analizy
              </Button>
            )}
            {alert.status !== "closed" && (
              <Button color="gray" variant="light" onClick={() => setClosing(true)}>
                Zamknij
              </Button>
            )}
            {alert.status === "closed" && (
              <Button variant="light" onClick={() => void setStatus("open")}>
                Otwórz ponownie
              </Button>
            )}
          </Group>
        )}
      </Group>

      <Card withBorder>
        <SimpleGrid cols={{ base: 2, md: 4 }}>
          <Field label="Komputer">{alert.host_name}</Field>
          <Field label="Konto">
            {alert.user_identity && alert.user_identity !== alert.user_name.toLowerCase()
              ? `${alert.user_name || "—"} (osoba: ${alert.user_identity})`
              : alert.user_name}
          </Field>
          <Field label="Adres źródłowy">{alert.source_ip}</Field>
          <Field label="Agent">{alert.agent_id}</Field>
          <Field label="Pierwsze zdarzenie">{formatDate(alert.first_seen)}</Field>
          <Field label="Ostatnie zdarzenie">{formatDate(alert.last_seen)}</Field>
          <Field label="Trafienia">{String(alert.hits)}</Field>
          <Field label="Silnik">{({ index_query: "zapytania (ClickHouse)", stream: "w locie", system: "reguła wbudowana", correlation: "korelacja (wiele źródeł)" } as Record<string, string>)[alert.engine] ?? alert.engine}</Field>
        </SimpleGrid>
        {Object.keys(alert.group_fields).length > 0 && (
          <Text size="sm" mt="sm">
            Klucz alertu:{" "}
            {Object.entries(alert.group_fields).map(([k, v]) => (
              <Code key={k} mr="xs">
                {k} = {v}
              </Code>
            ))}
          </Text>
        )}
        {alert.status === "closed" && (
          <Text size="sm" mt="sm" c="dimmed">
            Zamknął {alert.closed_by}, {formatDate(alert.closed_at)}: {alert.close_reason}
          </Text>
        )}
      </Card>

      <Group gap="xs">
        {around && (
          <Button component={Link} to={around} variant="light" size="xs" leftSection={<IconSearch size={14} />}>
            Zdarzenia z tego komputera ±15 min (Mímir)
          </Button>
        )}
        {alert.host_name && (
          <Button component={Link} to={`/alerts?status=all&host=${encodeURIComponent(alert.host_name)}`} variant="subtle" size="xs">
            Wszystkie alerty komputera
          </Button>
        )}
        {alert.user_name && (
          <Button component={Link} to={`/alerts?status=all&user=${encodeURIComponent(alert.user_name)}`} variant="subtle" size="xs">
            Wszystkie alerty konta
          </Button>
        )}
      </Group>

      {rule && (
        <Card withBorder>
          <Title order={4}>Reguła</Title>
          <AttributionLine a={attribution} />
          {rule.description && (
            <Text size="sm" mt="xs" style={{ whiteSpace: "pre-line" }}>
              {rule.description}
            </Text>
          )}
          {(alert.instructions || rule.instructions) && (
            <MAlert color="blue" mt="sm" title="Co zrobić">
              <Text size="sm" style={{ whiteSpace: "pre-line" }}>
                {alert.instructions || renderInstructions(rule.instructions, firstEvent)}
              </Text>
            </MAlert>
          )}
          <Group gap={4} mt="sm">
            {rule.tags.map((t) => (
              <Badge key={t} variant="outline" size="sm">
                {t}
              </Badge>
            ))}
          </Group>
        </Card>
      )}

      <SimpleGrid cols={{ base: 1, lg: 2 }}>
        <Card withBorder>
          <Title order={4} mb="sm">
            Przebieg i notatki
          </Title>
          <Timeline bulletSize={22} lineWidth={2}>
            <Timeline.Item bullet={<IconArrowsExchange size={12} />} title="Alert utworzony">
              <Text size="xs" c="dimmed">
                {formatDate(alert.created_at)} · silnik: {alert.engine}
              </Text>
            </Timeline.Item>
            {activity.map((a) => (
              <Timeline.Item
                key={a.id}
                bullet={a.kind === "note" ? <IconMessage size={12} /> : a.kind === "assign" ? <IconUserCheck size={12} /> : <IconArrowsExchange size={12} />}
                title={
                  a.kind === "note"
                    ? `Notatka – ${a.actor}`
                    : a.kind === "assign"
                      ? a.details?.to
                        ? `${a.actor} przypisał(a) do ${a.details.to}`
                        : `${a.actor} usunął(ęła) przypisanie`
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
                placeholder="Notatka: co sprawdzono, z kim rozmawiano, numer zgłoszenia…"
                autosize
                minRows={2}
                maxLength={4000}
                value={note}
                onChange={(e) => setNote(e.currentTarget.value)}
              />
              <Group justify="flex-end">
                <Button size="xs" disabled={!note.trim()} onClick={() => void addNote()}>
                  Dodaj notatkę
                </Button>
              </Group>
            </Stack>
          )}
        </Card>
        <Card withBorder>
          <Title order={4} mb="xs">
            Powiązane alerty ({related.length})
          </Title>
          <Text size="xs" c="dimmed" mb="xs">
            Ten sam komputer, konto albo osoba (to samo konto w AD, Entra ID i na VPN), ±24 h od zdarzeń tego alertu.
          </Text>
          {related.length === 0 ? (
            <Text size="sm" c="dimmed">
              Brak.
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
                        #{r.id} {r.rule_title}
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
          Zdarzenia ({events.length}
          {alert.hits > events.length ? ` z ${alert.hits}` : ""})
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

      <Modal opened={closing} onClose={() => setClosing(false)} title="Zamknij alert" centered>
        <Stack>
          <Textarea
            label="Powód"
            description="np. fałszywy alarm, wyjaśnione z użytkownikiem, incydent nr…"
            autosize
            minRows={2}
            value={reason}
            onChange={(e) => setReason(e.currentTarget.value)}
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setClosing(false)}>
              Wróć
            </Button>
            <Button onClick={() => void setStatus("closed", reason)}>Zamknij alert</Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}
