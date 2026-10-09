import { useCallback, useEffect, useState } from "react";
import {
  Accordion,
  Alert as MAlert,
  Anchor,
  Badge,
  Button,
  Card,
  Code,
  Group,
  Modal,
  SimpleGrid,
  Stack,
  Table,
  Text,
  Textarea,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconArrowLeft } from "@tabler/icons-react";
import { Link, useParams } from "react-router-dom";
import {
  alertStatusLabels,
  alertsApi,
  eventsApi,
  formatDate,
  levelLabels,
  type Alert,
  type AlertStatus,
  type EventDetail,
  type RuleInfo,
} from "../api";
import { useAuth } from "../auth";

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
  useEffect(() => {
    eventsApi
      .get(id, time)
      .then((r) => setEv(r.event))
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, [id, time]);
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

  const load = useCallback(() => {
    alertsApi
      .get(Number(id))
      .then((r) => {
        setAlert(r.alert);
        setEvents(r.events);
        setRule(r.rule);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [id]);
  useEffect(() => load(), [load]);

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
      const r = await alertsApi.setStatus(Number(id), s, why);
      setAlert(r.alert);
      setClosing(false);
      setReason("");
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    }
  };

  if (error) return <MAlert color="red">{error}</MAlert>;
  if (!alert) return null;
  const canEdit = user?.role === "admin" || user?.role === "analyst";
  const lv = levelLabels[alert.level];

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
        </div>
        {canEdit && (
          <Group>
            {alert.status === "open" && <Button onClick={() => void setStatus("acknowledged")}>Biorę do analizy</Button>}
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
          <Field label="Konto">{alert.user_name}</Field>
          <Field label="Adres źródłowy">{alert.source_ip}</Field>
          <Field label="Agent">{alert.agent_id}</Field>
          <Field label="Pierwsze zdarzenie">{formatDate(alert.first_seen)}</Field>
          <Field label="Ostatnie zdarzenie">{formatDate(alert.last_seen)}</Field>
          <Field label="Trafienia">{String(alert.hits)}</Field>
          <Field label="Silnik">{alert.engine}</Field>
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

      {rule && (
        <Card withBorder>
          <Title order={4}>Reguła</Title>
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
