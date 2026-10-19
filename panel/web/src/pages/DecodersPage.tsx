import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert as MAlert,
  Badge,
  Button,
  Code,
  Group,
  Modal,
  NumberInput,
  PasswordInput,
  ScrollArea,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  TextInput,
  Textarea,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconDownload, IconFileCode, IconFlask, IconHistory, IconPlus, IconWand } from "@tabler/icons-react";
import DecoderWizard from "./DecoderWizard";
import {
  ApiError,
  decodersApi,
  formatDate,
  type DecodeResult,
  type DecoderInfo,
  type DecoderTestResponse,
  type DecoderVersion,
} from "../api";
import { useLocation } from "react-router-dom";
import { useAuth } from "../auth";
import { lineDiff } from "../diff";

const newDecoderTemplate = `id: moje-urzadzenie
title: Moje urządzenie – logowania
description: |
  Co rozpoznaje dekoder i skąd przychodzą wiadomości.
version: 1
priority: 60
dataset: producent.produkt
match:
  # wszystkie warunki muszą być spełnione; any – co najmniej jedna alternatywa
  app: [sshd]
  # peer: [192.168.88.0/24]
  # host: [nas01]
  # regex: 'failed'
parser:
  type: regex   # kv | json | csv | regex | none
  patterns:
    - regex: 'Failed password for (?:invalid user )?(?P<user>\\S+) from (?P<src_ip>[0-9a-fA-F.:]+)'
      set: {event.action: login, event.outcome: failure}
    - regex: 'Accepted \\S+ for (?P<user>\\S+) from (?P<src_ip>[0-9a-fA-F.:]+)'
      set: {event.action: login, event.outcome: success}
fields:
  user.name: user
  source.ip: src_ip
samples:
  - '<38>Oct  9 13:00:00 nas01 sshd[812]: Failed password for root from 203.0.113.9 port 51234 ssh2'
`;

const actionLabels: Record<DecoderVersion["action"], string> = {
  saved: "zapisano definicję",
  enabled: "włączono",
  disabled: "wyłączono",
  reverted: "cofnięto zmiany z panelu",
};

const keyEventFields = ["event.action", "event.outcome", "user.name", "source.ip", "host.name"];

function ResultRow({ r, candidate }: { r: DecodeResult; candidate?: string }) {
  const [open, setOpen] = useState(false);
  const color = r.error ? "red" : r.dataset === "syslog.generic" ? "gray" : r.decoder === candidate ? "green" : "blue";
  return (
    <>
      <Table.Tr style={{ cursor: "pointer" }} onClick={() => setOpen((o) => !o)}>
        <Table.Td>
          <Badge color={color} variant={r.decoder === candidate ? "filled" : "light"}>
            {r.error ? "kwarantanna" : r.decoder || "brak"}
          </Badge>
          {r.decoder && !r.pattern && !r.error && (
            <Tooltip label="Dekoder pasuje, ale żaden wzorzec nie rozebrał treści – zostaje tylko tekst">
              <Badge color="orange" variant="outline" ml={4}>
                bez wzorca
              </Badge>
            </Tooltip>
          )}
          {candidate && r.candidate && r.decoder !== candidate && (
            <Tooltip label="Testowany dekoder pasuje, ale wcześniej wybrano inny (wyższy priorytet) – zmień priority albo match">
              <Badge color="yellow" variant="outline" ml={4}>
                przesłonięty
              </Badge>
            </Tooltip>
          )}
        </Table.Td>
        <Table.Td>
          <Text size="xs">{r.dataset}</Text>
        </Table.Td>
        <Table.Td>
          <Group gap={4}>
            {keyEventFields
              .filter((k) => r.event[k])
              .map((k) => (
                <Badge key={k} size="xs" variant="outline" tt="none">
                  {k}: {r.event[k]}
                </Badge>
              ))}
          </Group>
          <Text size="xs" c="dimmed" ff="monospace" lineClamp={open ? undefined : 1} style={{ wordBreak: "break-all" }}>
            {r.raw}
          </Text>
        </Table.Td>
      </Table.Tr>
      {open && (
        <Table.Tr>
          <Table.Td colSpan={3}>
            {r.error && (
              <MAlert color="red" mb="xs">
                {r.error}
              </MAlert>
            )}
            <SimpleGrid cols={{ base: 1, md: 3 }} spacing="xs">
              <div>
                <Text size="xs" fw={600}>
                  Nagłówek ({r.header.format})
                </Text>
                <Code block fz="xs">
                  {[
                    r.header.time && `czas: ${formatDate(r.header.time)}`,
                    r.header.host && `host: ${r.header.host}`,
                    r.header.app && `program: ${r.header.app}${r.header.pid ? `[${r.header.pid}]` : ""}`,
                    r.header.severity && `poziom: ${r.header.severity} (facility ${r.header.facility})`,
                    `treść: ${r.header.message}`,
                  ]
                    .filter(Boolean)
                    .join("\n")}
                </Code>
              </div>
              <div>
                <Text size="xs" fw={600}>
                  Zdarzenie
                </Text>
                <Code block fz="xs">
                  {Object.entries(r.event)
                    .sort()
                    .map(([k, v]) => `${k}: ${v}`)
                    .join("\n")}
                </Code>
              </div>
              <div>
                <Text size="xs" fw={600}>
                  Pola ({Object.keys(r.fields).length})
                </Text>
                <ScrollArea.Autosize mah={240}>
                  <Code block fz="xs">
                    {Object.entries(r.fields)
                      .sort()
                      .map(([k, v]) => `${k}: ${v}`)
                      .join("\n") || "—"}
                  </Code>
                </ScrollArea.Autosize>
              </div>
            </SimpleGrid>
          </Table.Td>
        </Table.Tr>
      )}
    </>
  );
}

// Edytor: definicja YAML, próbki (wklejone albo z bazy), test na zestawie
// działających dekoderów z tym na swoim miejscu, zapis (administrator).
function DecoderEditor({
  decoder,
  admin,
  samplesAvailable,
  onSaved,
  initialSource,
}: {
  decoder: DecoderInfo | null;
  admin: boolean;
  samplesAvailable: boolean;
  onSaved: () => void;
  initialSource?: string;
}) {
  const [source, setSource] = useState(decoder?.source ?? initialSource ?? newDecoderTemplate);
  const [samples, setSamples] = useState("");
  const [peer, setPeer] = useState("");
  const [hours, setHours] = useState<number | string>(24);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [res, setRes] = useState<DecoderTestResponse | null>(null);
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);

  const run = async () => {
    setBusy(true);
    try {
      const lines = samples.split("\n").filter((l) => l.trim() !== "");
      setRes(await decodersApi.test(source, lines, peer.trim()));
    } catch (e) {
      setRes({ ok: false, error: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  const load = async (own: boolean) => {
    setLoading(true);
    try {
      const r = await decodersApi.samples({ decoder: own ? decoder?.id : undefined, peer: peer.trim(), hours: Number(hours) || 24 });
      if (r.samples.length === 0) notifications.show({ color: "gray", message: "Brak wiadomości w wybranym okresie" });
      setSamples(r.samples.map((s) => s.raw).join("\n"));
      // Test używa jednego adresu nadawcy: próbki od jednego urządzenia – jego adres (warunek peer).
      const peers = new Set(r.samples.map((s) => s.peer));
      if (!peer.trim() && peers.size === 1) setPeer([...peers][0]);
      else if (!peer.trim() && peers.size > 1)
        notifications.show({ color: "yellow", message: "Próbki od różnych nadawców – dekodery z warunkiem peer sprawdź z filtrem nadawcy" });
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setLoading(false);
    }
  };

  const save = async () => {
    const id = /^id:\s*(\S+)/m.exec(source)?.[1] ?? "";
    if (!id) {
      notifications.show({ color: "red", message: "Brak id w definicji" });
      return;
    }
    if (decoder && id !== decoder.id) {
      notifications.show({ color: "red", message: `Id w definicji (${id}) różni się od edytowanego dekodera (${decoder.id})` });
      return;
    }
    setSaving(true);
    try {
      const r = await decodersApi.save(id, source, note.trim());
      notifications.show({ color: "green", message: `Rewizja ${r.revision}: ${r.message}` });
      setNote("");
      onSaved();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setSaving(false);
    }
  };

  const s = res?.summary;
  return (
    <Stack gap="xs">
      <Text size="xs" c="dimmed">
        Test dekoduje próbki zestawem działających dekoderów, w którym ta definicja zastępuje swój odpowiednik – widać więc też, który
        dekoder wygrywa (priorytet). Pusta lista próbek – test na próbkach z definicji (<Code>samples</Code>). Nic nie jest zapisywane.
      </Text>
      <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="xs">
        <Textarea
          label="Definicja (YAML)"
          autosize
          minRows={16}
          maxRows={30}
          spellCheck={false}
          styles={{ input: { fontFamily: "monospace", fontSize: 12 } }}
          value={source}
          onChange={(e) => setSource(e.currentTarget.value)}
        />
        <Stack gap="xs">
          <Textarea
            label="Próbki – jedna wiadomość w wierszu, z nagłówkiem syslog"
            autosize
            minRows={8}
            maxRows={16}
            spellCheck={false}
            styles={{ input: { fontFamily: "monospace", fontSize: 12 } }}
            value={samples}
            onChange={(e) => setSamples(e.currentTarget.value)}
            placeholder="<134>Oct  9 20:54:19 MikroTik user admin logged in from 192.168.88.10 via winbox"
          />
          <Group gap="xs" align="flex-end">
            <TextInput
              label="Adres nadawcy"
              description="dla warunku peer"
              placeholder="192.168.88.1"
              w={160}
              value={peer}
              onChange={(e) => setPeer(e.currentTarget.value)}
            />
            {samplesAvailable && (
              <>
                <NumberInput label="Z ostatnich godzin" w={130} min={1} max={168} value={hours} onChange={setHours} />
                <Button variant="default" leftSection={<IconDownload size={14} />} loading={loading} onClick={() => void load(false)}>
                  Nierozpoznane
                </Button>
                {decoder && (
                  <Button variant="default" leftSection={<IconDownload size={14} />} loading={loading} onClick={() => void load(true)}>
                    Obsłużone przez ten
                  </Button>
                )}
              </>
            )}
          </Group>
          <Group>
            <Button leftSection={<IconFlask size={16} />} loading={busy} onClick={() => void run()}>
              Testuj
            </Button>
          </Group>
          {admin && (
            <Group align="flex-end" gap="xs">
              <TextInput
                label="Opis zmiany"
                placeholder="np. dodany wzorzec logowania przez VPN"
                style={{ flex: 1 }}
                value={note}
                onChange={(e) => setNote(e.currentTarget.value)}
              />
              <Button color="green" loading={saving} onClick={() => void save()}>
                Zapisz i wdroż
              </Button>
            </Group>
          )}
        </Stack>
      </SimpleGrid>
      {res && !res.ok && <MAlert color="red">{res.error}</MAlert>}
      {res?.ok && s && (
        <Stack gap="xs">
          <Group gap="xs">
            <Text size="sm">Wiadomości: {s.total}</Text>
            {res.decoder && <Badge color="green">ten dekoder: {s.candidate}</Badge>}
            <Badge color="blue">inne dekodery: {s.other}</Badge>
            <Badge color="gray">nierozpoznane: {s.generic}</Badge>
            {s.errors > 0 && <Badge color="red">kwarantanna: {s.errors}</Badge>}
            {s.no_pattern > 0 && <Badge color="orange">bez wzorca: {s.no_pattern}</Badge>}
          </Group>
          <Table.ScrollContainer minWidth={760}>
            <Table verticalSpacing={4}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th w={220}>Dekoder</Table.Th>
                  <Table.Th w={160}>Zbiór danych</Table.Th>
                  <Table.Th>Wynik (kliknij – szczegóły)</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {res.results?.map((r, i) => <ResultRow key={i} r={r} candidate={res.decoder?.id} />)}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Stack>
      )}
    </Stack>
  );
}

function Versions({ id }: { id: string }) {
  const [versions, setVersions] = useState<DecoderVersion[]>([]);
  const [sel, setSel] = useState<number | null>(null);
  useEffect(() => {
    decodersApi
      .versions(id)
      .then((r) => {
        setVersions(r.versions);
        setSel(r.versions[0]?.id ?? null);
      })
      .catch(() => setVersions([]));
  }, [id]);
  const idx = versions.findIndex((v) => v.id === sel);
  const cur = versions[idx];
  const prev = versions.slice(idx + 1).find((v) => v.source !== "");
  const diff = useMemo(() => (cur && prev && cur.source ? lineDiff(prev.source, cur.source) : null), [cur, prev]);
  if (versions.length === 0) return <Text size="sm">Brak zmian z panelu – działa wersja wbudowana w program.</Text>;
  return (
    <Stack gap="xs">
      <Group gap="xs">
        {versions.map((v) => (
          <Badge key={v.id} variant={v.id === sel ? "filled" : "light"} style={{ cursor: "pointer" }} onClick={() => setSel(v.id)}>
            r{v.revision} · {formatDate(v.changed_at)}
          </Badge>
        ))}
      </Group>
      {cur && (
        <Text size="xs" c="dimmed">
          r{cur.revision}: {actionLabels[cur.action]} – {cur.changed_by}, {formatDate(cur.changed_at)}
          {cur.note ? ` · „${cur.note}”` : ""}
        </Text>
      )}
      {cur?.source && (
        <ScrollArea.Autosize mah={460}>
          {diff ? (
            <Code block fz="xs">
              {diff.map((d, i) => (
                <div
                  key={i}
                  style={{ background: d.op === "+" ? "rgba(47,158,68,.15)" : d.op === "-" ? "rgba(224,49,49,.15)" : undefined }}
                >
                  {d.op} {d.line}
                </div>
              ))}
            </Code>
          ) : (
            <Code block>{cur.source}</Code>
          )}
        </ScrollArea.Autosize>
      )}
    </Stack>
  );
}

export default function DecodersPage() {
  const { user } = useAuth();
  const admin = user?.role === "admin";
  const canTest = admin || user?.role === "analyst";
  const [list, setList] = useState<DecoderInfo[]>([]);
  const [delivery, setDelivery] = useState(true);
  const [samplesOn, setSamplesOn] = useState(false);
  const [error, setError] = useState("");
  const [show, setShow] = useState<DecoderInfo | null>(null);
  const [creating, setCreating] = useState(false);
  const [wizard, setWizard] = useState(false);
  const [draft, setDraft] = useState<string | undefined>(undefined);
  // Definicja z kreatora otwartego w kwarantannie – do dopracowania w edytorze.
  const location = useLocation();
  useEffect(() => {
    const d = (location.state as { draft?: string } | null)?.draft;
    if (d) {
      setDraft(d);
      setCreating(true);
      window.history.replaceState({}, "");
    }
  }, [location.state]);
  const [tab, setTab] = useState<string | null>("source");
  const [action, setAction] = useState<{ d: DecoderInfo; kind: "disable" | "enable" | "revert" } | null>(null);
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const [needPassword, setNeedPassword] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    decodersApi
      .list()
      .then((r) => {
        const sorted = [...r.decoders].sort((a, b) => (a.order || 999) - (b.order || 999) || a.id.localeCompare(b.id));
        setList(sorted);
        setDelivery(r.delivery);
        setSamplesOn(r.samples);
        setShow((s) => (s ? (sorted.find((d) => d.id === s.id) ?? null) : s));
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);
  useEffect(() => load(), [load]);

  const weakening = action?.kind === "disable" || (action?.kind === "revert" && action.d.origin === "custom");
  const apply = async () => {
    if (!action) return;
    setBusy(true);
    try {
      const r =
        action.kind === "revert"
          ? await decodersApi.revert(action.d.id, reason, password)
          : await decodersApi.setEnabled(action.d.id, action.kind === "enable", reason, password);
      notifications.show({ color: "green", message: r.message });
      if (action.kind === "revert" && action.d.origin === "custom") setShow(null);
      setAction(null);
      setReason("");
      setPassword("");
      setNeedPassword(false);
      load();
    } catch (e) {
      if (e instanceof ApiError && e.code === "reauth_required") setNeedPassword(true);
      else notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack>
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>Dekodery syslog</Title>
          <Text c="dimmed" size="sm" maw={860}>
            Dekoder rozpoznaje wiadomości z urządzenia (warunki <Code>match</Code>), rozbiera treść (kv, JSON, CSV, wzorce) i przypisuje
            pola zdarzenia – na nich działają reguły detekcji (<Code>product: fortigate</Code>, <Code>mikrotik</Code>…). Dekodery
            sprawdzane są po kolei (wyższy priorytet pierwszy); wiadomość bez dekodera trafia jako <Code>syslog.generic</Code>. Zmiany
            z panelu działają w normalizatorach w ciągu kilku sekund i nie zmieniają zdarzeń już zapisanych.
          </Text>
        </div>
        {canTest && (
          <Group gap="xs" wrap="nowrap">
          <Button variant="light" leftSection={<IconWand size={16} />} onClick={() => setWizard(true)}>
            Kreator z próbek
          </Button>
          <Button
            leftSection={<IconPlus size={16} />}
            onClick={() => {
              setDraft(undefined);
              setCreating(true);
            }}
          >
            Nowy dekoder
          </Button>
          </Group>
        )}
      </Group>
      {error && <MAlert color="red">{error}</MAlert>}
      {!delivery && (
        <MAlert color="orange">
          Panel nie jest połączony z NATS – zapisane zmiany trafią do normalizatorów dopiero po przywróceniu połączenia.
        </MAlert>
      )}
      <Table.ScrollContainer minWidth={900}>
        <Table striped highlightOnHover verticalSpacing="xs">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Włączony</Table.Th>
              <Table.Th>Kolejność</Table.Th>
              <Table.Th>Dekoder</Table.Th>
              <Table.Th>Zbiór danych</Table.Th>
              <Table.Th>Priorytet</Table.Th>
              <Table.Th>Zmiany</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {list.map((d) => (
              <Table.Tr
                key={d.id}
                style={{ cursor: "pointer", opacity: d.enabled ? 1 : 0.55 }}
                onClick={() => {
                  setShow(d);
                  setTab("source");
                }}
              >
                <Table.Td onClick={(e) => e.stopPropagation()}>
                  <Switch
                    size="sm"
                    checked={d.enabled}
                    disabled={!admin}
                    onChange={(e) => setAction({ d, kind: e.currentTarget.checked ? "enable" : "disable" })}
                    aria-label="dekoder włączony"
                  />
                </Table.Td>
                <Table.Td>{d.order || "—"}</Table.Td>
                <Table.Td maw={440}>
                  <Group gap={6}>
                    <Text size="sm" fw={500}>
                      {d.title}
                    </Text>
                    {d.origin === "builtin" ? (
                      <Badge size="xs" variant="light" color="gray">
                        wbudowany
                      </Badge>
                    ) : (
                      <Badge size="xs" variant="light" color="grape">
                        własny
                      </Badge>
                    )}
                    {d.modified && (
                      <Badge size="xs" variant="outline" color="grape">
                        zmieniony w panelu
                      </Badge>
                    )}
                    {d.error && (
                      <Tooltip label={d.error} multiline w={360}>
                        <Badge size="xs" color="red">
                          błąd
                        </Badge>
                      </Tooltip>
                    )}
                  </Group>
                  <Text size="xs" c="dimmed" ff="monospace">
                    {d.id} · v{d.version} · próbek {d.samples}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Code>{d.dataset}</Code>
                </Table.Td>
                <Table.Td>{d.priority}</Table.Td>
                <Table.Td>
                  {d.updated_by ? (
                    <Text size="xs">
                      r{d.revision} · {d.updated_by}, {formatDate(d.updated_at)}
                    </Text>
                  ) : (
                    <Text size="xs" c="dimmed">
                      —
                    </Text>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={!!show} onClose={() => setShow(null)} title={show?.title} size="90%">
        {show && (
          <Stack gap="xs">
            <Group justify="space-between">
              <Text size="xs" c="dimmed">
                {show.id} · {show.dataset} · priorytet {show.priority}
                {show.revision ? ` · rewizja ${show.revision} (${show.updated_by}, ${formatDate(show.updated_at)})` : ""}
              </Text>
              {admin && (show.modified || show.origin === "custom") && (
                <Button size="xs" variant="subtle" color="red" onClick={() => setAction({ d: show, kind: "revert" })}>
                  {show.origin === "custom" ? "Usuń dekoder" : "Przywróć wersję wbudowaną"}
                </Button>
              )}
            </Group>
            {show.description && (
              <Text size="sm" style={{ whiteSpace: "pre-line" }}>
                {show.description}
              </Text>
            )}
            <Tabs value={tab} onChange={setTab}>
              <Tabs.List>
                <Tabs.Tab value="source" leftSection={<IconFileCode size={14} />}>
                  Definicja
                </Tabs.Tab>
                {canTest && (
                  <Tabs.Tab value="edit" leftSection={<IconFlask size={14} />}>
                    {admin ? "Edycja i test" : "Test"}
                  </Tabs.Tab>
                )}
                <Tabs.Tab value="versions" leftSection={<IconHistory size={14} />}>
                  Historia
                </Tabs.Tab>
                {show.builtin_source && <Tabs.Tab value="builtin">Wersja wbudowana</Tabs.Tab>}
              </Tabs.List>
              <Tabs.Panel value="source" pt="xs">
                <ScrollArea.Autosize mah={560}>
                  <Code block>{show.source}</Code>
                </ScrollArea.Autosize>
              </Tabs.Panel>
              <Tabs.Panel value="edit" pt="xs">
                {tab === "edit" && <DecoderEditor decoder={show} admin={admin} samplesAvailable={samplesOn} onSaved={load} />}
              </Tabs.Panel>
              <Tabs.Panel value="versions" pt="xs">
                {tab === "versions" && <Versions id={show.id} />}
              </Tabs.Panel>
              <Tabs.Panel value="builtin" pt="xs">
                {show.builtin_source && (
                  <ScrollArea.Autosize mah={560}>
                    <Code block fz="xs">
                      {lineDiff(show.builtin_source, show.source).map((d, i) => (
                        <div
                          key={i}
                          style={{ background: d.op === "+" ? "rgba(47,158,68,.15)" : d.op === "-" ? "rgba(224,49,49,.15)" : undefined }}
                        >
                          {d.op} {d.line}
                        </div>
                      ))}
                    </Code>
                  </ScrollArea.Autosize>
                )}
              </Tabs.Panel>
            </Tabs>
          </Stack>
        )}
      </Modal>

      <Modal opened={creating} onClose={() => setCreating(false)} title="Nowy dekoder" size="90%">
        {creating && (
          <DecoderEditor
            decoder={null}
            admin={admin}
            samplesAvailable={samplesOn}
            initialSource={draft}
            onSaved={() => {
              setCreating(false);
              load();
            }}
          />
        )}
      </Modal>

      <Modal opened={wizard} onClose={() => setWizard(false)} title="Kreator dekodera – zaznacz pola w przykładowych wiadomościach" size="95%">
        {wizard && (
          <DecoderWizard
            initialSamples={[]}
            admin={admin}
            samplesAvailable={samplesOn}
            onEdit={(yaml) => {
              setDraft(yaml);
              setWizard(false);
              setCreating(true);
            }}
            onSaved={() => {
              setWizard(false);
              load();
            }}
          />
        )}
      </Modal>

      <Modal
        opened={!!action}
        onClose={() => {
          setAction(null);
          setNeedPassword(false);
        }}
        title={
          action
            ? action.kind === "revert"
              ? action.d.origin === "custom"
                ? `Usunięcie dekodera „${action.d.title}”`
                : `Przywrócenie wbudowanej wersji „${action.d.title}”`
              : `${action.kind === "disable" ? "Wyłączenie" : "Włączenie"} dekodera „${action.d.title}”`
            : ""
        }
        centered
      >
        {action && (
          <Stack>
            {weakening && (
              <MAlert color="orange">
                Wiadomości tego urządzenia trafią do innego dekodera albo jako syslog.generic – reguły detekcji dla{" "}
                <Code>{action.d.dataset}</Code> przestaną je widzieć. Podaj powód (trafi do audytu) i potwierdź hasłem.
              </MAlert>
            )}
            {action.kind === "revert" && action.d.origin === "builtin" && (
              <Text size="sm">Własna definicja zostanie usunięta (zostaje w historii), zacznie działać wersja wbudowana w program.</Text>
            )}
            <Textarea
              label="Powód"
              description={weakening ? "np. błędnie rozpoznaje wiadomości z drukarek" : "opcjonalnie"}
              autosize
              minRows={2}
              value={reason}
              onChange={(e) => setReason(e.currentTarget.value)}
            />
            {(needPassword || weakening) && (
              <PasswordInput label="Twoje hasło" value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
            )}
            <Group justify="flex-end">
              <Button
                color={weakening ? "red" : undefined}
                loading={busy}
                disabled={weakening && (reason.trim().length < 3 || !password)}
                onClick={() => void apply()}
              >
                {action.kind === "revert"
                  ? action.d.origin === "custom"
                    ? "Usuń dekoder"
                    : "Przywróć"
                  : action.kind === "disable"
                    ? "Wyłącz dekoder"
                    : "Włącz dekoder"}
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
