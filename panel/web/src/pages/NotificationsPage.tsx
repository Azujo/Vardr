// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  Group,
  Modal,
  MultiSelect,
  Select,
  PasswordInput,
  SegmentedControl,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAnchor, IconBell, IconPlus, IconSend, IconTrash } from "@tabler/icons-react";
import {
  ApiError,
  alertsApi,
  formatDate,
  levelLabels,
  notifyApi,
  notifyEventLabels,
  type AlertFilter,
  type AlertLevel,
  type ChannelRequest,
  type NotifyChannel,
  type NotifyEvent,
  type NotifyLogEntry,
} from "../api";

const allEvents: NotifyEvent[] = ["alert", "incident", "health", "anchor"];

function errMsg(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

const levels: AlertLevel[] = ["informational", "low", "medium", "high", "critical"];

// Filtr alertów detekcji na kanale: od poziomu i wybór reguł.
function AlertFilterEditor({
  value,
  rules,
  onSave,
}: {
  value: AlertFilter;
  rules: { value: string; label: string }[];
  onSave: (f: AlertFilter) => void;
}) {
  const [f, setF] = useState<AlertFilter>(value);
  useEffect(() => setF(value), [value]);
  const mode = f.rules_mode ?? "all";
  const changed = JSON.stringify(f) !== JSON.stringify(value);
  return (
    <Group gap="xs" align="flex-end" wrap="wrap">
      <Select
        size="xs"
        w={170}
        label="Alerty od poziomu"
        allowDeselect={false}
        data={levels.map((l) => ({ value: l, label: levelLabels[l].label }))}
        value={f.min_level ?? "informational"}
        onChange={(v) => setF({ ...f, min_level: v === "informational" ? undefined : (v as AlertLevel) })}
      />
      <Select
        size="xs"
        w={200}
        label="Reguły"
        allowDeselect={false}
        data={[
          { value: "all", label: "wszystkie" },
          { value: "only", label: "tylko wybrane" },
          { value: "except", label: "wszystkie poza wybranymi" },
        ]}
        value={mode}
        onChange={(v) =>
          setF(v === "all" ? { min_level: f.min_level } : { ...f, rules_mode: v as "only" | "except", rules: f.rules ?? [] })
        }
      />
      {mode !== "all" && (
        <MultiSelect
          size="xs"
          miw={260}
          maw={520}
          label={mode === "only" ? "Wysyłaj tylko z reguł" : "Nie wysyłaj z reguł"}
          searchable
          data={rules}
          value={f.rules ?? []}
          onChange={(v) => setF({ ...f, rules: v })}
        />
      )}
      {changed && (
        <Button size="xs" disabled={mode !== "all" && !(f.rules ?? []).length} onClick={() => onSave(f)}>
          Zapisz filtr
        </Button>
      )}
    </Group>
  );
}

// Kanały powiadomień: dokąd Vardr wysyła wiadomości poza system.
export default function NotificationsPage() {
  const [channels, setChannels] = useState<NotifyChannel[]>([]);
  const [log, setLog] = useState<NotifyLogEntry[]>([]);
  const [anchorHour, setAnchorHour] = useState(-1);
  const [relay, setRelay] = useState(true);
  const [error, setError] = useState("");
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState<{ name: string; kind: "discord" | "webhook"; url: string; events: NotifyEvent[] }>({
    name: "",
    kind: "discord",
    url: "",
    events: ["alert", "health", "anchor"],
  });
  // Zmiana wymagająca hasła (wyłączenie, rezygnacja z powiadomień, usunięcie).
  const [pending, setPending] = useState<{ label: string; run: (pw: string) => Promise<void> } | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [ruleOptions, setRuleOptions] = useState<{ value: string; label: string }[]>([]);
  useEffect(() => {
    alertsApi
      .rules()
      .then((r) => setRuleOptions(r.rules.map((x) => ({ value: x.id, label: x.title }))))
      .catch(() => setRuleOptions([]));
  }, []);

  const load = useCallback(() => {
    notifyApi
      .list()
      .then((r) => {
        setChannels(r.channels);
        setLog(r.log);
        setAnchorHour(r.anchor_hour);
        setRelay(r.relay_configured);
        setError("");
      })
      .catch((e) => setError(errMsg(e)));
  }, []);
  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [load]);

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await notifyApi.create({ ...form, enabled: true });
      notifications.show({ color: "green", message: "Kanał dodany – wyślij test, żeby sprawdzić adres." });
      setAdding(false);
      setForm({ name: "", kind: "discord", url: "", events: ["alert", "health", "anchor"] });
      load();
    } catch (err) {
      notifications.show({ color: "red", message: errMsg(err) });
    } finally {
      setBusy(false);
    }
  };

  // Zmiana kanału; gdy serwer zażąda hasła – okno z hasłem i ponowienie.
  const update = async (c: NotifyChannel, patch: Partial<ChannelRequest>, label: string) => {
    const req: ChannelRequest = { name: c.name, events: c.events, alert_filter: c.alert_filter, enabled: c.enabled, ...patch };
    try {
      await notifyApi.update(c.id, req);
      load();
    } catch (e) {
      if (e instanceof ApiError && e.code === "reauth_required") {
        setPending({
          label,
          run: async (pw) => {
            await notifyApi.update(c.id, { ...req, password: pw });
            load();
          },
        });
      } else notifications.show({ color: "red", message: errMsg(e) });
    }
  };

  const confirm = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pending) return;
    setBusy(true);
    try {
      await pending.run(password);
      notifications.show({ color: "green", message: "Zmiana zapisana." });
      setPending(null);
      setPassword("");
    } catch (err) {
      notifications.show({ color: "red", message: errMsg(err) });
    } finally {
      setBusy(false);
    }
  };

  const action = async (fn: () => Promise<{ message: string }>) => {
    try {
      const r = await fn();
      notifications.show({ color: "green", message: r.message });
    } catch (e) {
      notifications.show({ color: "red", message: errMsg(e) });
    } finally {
      load();
    }
  };

  return (
    <Stack>
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>Powiadomienia</Title>
          <Text c="dimmed" size="sm" maw={820}>
            Kanały, na które Vardr wysyła wiadomości poza system: alerty zdrowia (z Grafany) i codzienną kotwicę archiwum
            Urd {anchorHour >= 0 && `(o ${anchorHour}:00)`} – hash najnowszego manifestu, którego kopia u odbiorcy jest
            niezależnym dowodem nienaruszalności archiwum. Później te same kanały dostaną alerty detekcji. Adres webhooka jest
            sekretem: panel pokazuje tylko jego początek i koniec.
          </Text>
        </div>
        <Group>
          <Button variant="light" leftSection={<IconAnchor size={18} />} onClick={() => void action(notifyApi.sendAnchor)}>
            Wyślij kotwicę teraz
          </Button>
          <Button leftSection={<IconPlus size={18} />} onClick={() => setAdding(true)}>
            Dodaj kanał
          </Button>
        </Group>
      </Group>
      {error && <Alert color="red">{error}</Alert>}
      {!relay && (
        <Alert color="orange">
          Alerty z Grafany nie są przekazywane – siem-api nie ma SIEM_ALERT_RELAY_TOKEN (README, sekcja Alerty).
        </Alert>
      )}
      {channels.length > 0 && !channels.some((c) => c.enabled && c.events.includes("alert")) && (
        <Alert color="orange" icon={<IconBell />}>
          Żaden włączony kanał nie odbiera alertów detekcji (Gjallarhorn) – alerty są tylko w panelu. Zaznacz „
          {notifyEventLabels.alert}” przy kanale, który ma je dostawać.
        </Alert>
      )}
      {channels.length === 0 && (
        <Alert color="gray" icon={<IconBell />}>
          Nie ma jeszcze kanałów – alerty i kotwica nigdzie nie wychodzą. Dodaj np. webhook kanału Discorda (Ustawienia
          kanału → Integracje → Webhooki → Kopiuj adres URL).
        </Alert>
      )}

      {channels.map((c) => (
        <Card withBorder key={c.id}>
          <Group justify="space-between" align="flex-start">
            <Stack gap={4}>
              <Group gap="xs">
                <Text fw={600}>{c.name}</Text>
                <Badge variant="light">{c.kind === "discord" ? "Discord" : "webhook"}</Badge>
                <Text size="xs" c="dimmed" ff="monospace">
                  {c.url_hint}
                </Text>
              </Group>
              <Group gap="lg">
                {allEvents.map((ev) => (
                  <Checkbox
                    key={ev}
                    label={notifyEventLabels[ev]}
                    checked={c.events.includes(ev)}
                    onChange={(e) => {
                      const on = e.currentTarget.checked;
                      const events = on ? [...c.events, ev] : c.events.filter((x) => x !== ev);
                      void update(c, { events }, `rezygnacja z: ${notifyEventLabels[ev]}`);
                    }}
                  />
                ))}
              </Group>
              {c.events.includes("alert") && (
                <AlertFilterEditor
                  value={c.alert_filter ?? {}}
                  rules={ruleOptions}
                  onSave={(f) => void update(c, { alert_filter: f }, "zawężenie alertów wysyłanych na kanał")}
                />
              )}
              <Text size="xs" c={c.last_error && (!c.last_ok_at || c.last_error_at! > c.last_ok_at) ? "red" : "dimmed"}>
                {c.last_ok_at ? `ostatnia udana wysyłka ${formatDate(c.last_ok_at)}` : "jeszcze nic nie wysłano"}
                {c.last_error && c.last_error_at && ` • ostatni błąd ${formatDate(c.last_error_at)}: ${c.last_error}`}
              </Text>
            </Stack>
            <Group gap="xs">
              <Switch
                label="włączony"
                checked={c.enabled}
                onChange={(e) => void update(c, { enabled: e.currentTarget.checked }, "wyłączenie kanału")}
              />
              <Button size="xs" variant="light" leftSection={<IconSend size={14} />} onClick={() => void action(() => notifyApi.test(c.id))}>
                Test
              </Button>
              <Button
                size="xs"
                variant="subtle"
                color="red"
                leftSection={<IconTrash size={14} />}
                onClick={() =>
                  setPending({
                    label: `usunięcie kanału „${c.name}”`,
                    run: async (pw) => {
                      await notifyApi.remove(c.id, pw);
                      load();
                    },
                  })
                }
              >
                Usuń
              </Button>
            </Group>
          </Group>
        </Card>
      ))}

      {log.length > 0 && (
        <Stack gap="xs">
          <Title order={4}>Ostatnie wysyłki</Title>
          <Table.ScrollContainer minWidth={800}>
            <Table striped verticalSpacing={4}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Czas</Table.Th>
                  <Table.Th>Kanał</Table.Th>
                  <Table.Th>Rodzaj</Table.Th>
                  <Table.Th>Treść</Table.Th>
                  <Table.Th>Wynik</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {log.map((l) => (
                  <Table.Tr key={l.id}>
                    <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(l.at)}</Table.Td>
                    <Table.Td>{l.channel}</Table.Td>
                    <Table.Td>{notifyEventLabels[l.event] ?? l.event}</Table.Td>
                    <Table.Td maw={380}>
                      <Text size="sm" lineClamp={1}>
                        {l.title}
                      </Text>
                      {l.anchor_sha256 && (
                        <Tooltip label={l.anchor_sha256} maw={600} multiline>
                          <Text size="xs" ff="monospace" c="dimmed">
                            #{l.anchor_seq} {l.anchor_sha256.slice(0, 16)}…{" "}
                            {l.anchor_match === true && <Badge size="xs" color="green" variant="light">zgodna z łańcuchem</Badge>}
                            {l.anchor_match === false && <Badge size="xs" color="red">NIEZGODNA z łańcuchem</Badge>}
                          </Text>
                        </Tooltip>
                      )}
                    </Table.Td>
                    <Table.Td>
                      {l.ok ? (
                        <Badge color="green" variant="light">wysłano</Badge>
                      ) : (
                        <Tooltip label={l.error} maw={500} multiline>
                          <Badge color="red" variant="light">błąd</Badge>
                        </Tooltip>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Stack>
      )}

      <Modal opened={adding} onClose={() => setAdding(false)} title="Nowy kanał powiadomień" centered>
        <form onSubmit={add}>
          <Stack gap="sm">
            <SegmentedControl
              value={form.kind}
              onChange={(v) => setForm({ ...form, kind: v as "discord" | "webhook" })}
              data={[
                { value: "discord", label: "Discord" },
                { value: "webhook", label: "Webhook (JSON)" },
              ]}
            />
            <TextInput label="Nazwa" required value={form.name} onChange={(e) => setForm({ ...form, name: e.currentTarget.value })} />
            <PasswordInput
              label="Adres webhooka"
              description={
                form.kind === "discord"
                  ? "https://discord.com/api/webhooks/… – traktuj jak hasło"
                  : "https://… – Vardr wysyła POST z JSON {event, severity, title, text, fields, at}"
              }
              required
              value={form.url}
              onChange={(e) => setForm({ ...form, url: e.currentTarget.value })}
            />
            <Checkbox.Group
              label="Co wysyłać"
              value={form.events}
              onChange={(v) => setForm({ ...form, events: v as NotifyEvent[] })}
            >
              <Stack gap={4} mt={4}>
                {allEvents.map((ev) => (
                  <Checkbox key={ev} value={ev} label={notifyEventLabels[ev]} />
                ))}
              </Stack>
            </Checkbox.Group>
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setAdding(false)}>
                Anuluj
              </Button>
              <Button type="submit" loading={busy}>
                Dodaj
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      <Modal opened={!!pending} onClose={() => setPending(null)} title="Potwierdź hasłem" centered>
        <form onSubmit={confirm}>
          <Stack gap="sm">
            <Text size="sm">
              {pending?.label} – ta zmiana ogranicza, co wychodzi poza system (np. kotwice archiwum), dlatego wymaga hasła.
            </Text>
            <PasswordInput
              label="Twoje hasło"
              required
              autoFocus
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
            />
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setPending(null)}>
                Wróć
              </Button>
              <Button type="submit" color="orange" loading={busy}>
                Potwierdź
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Stack>
  );
}
