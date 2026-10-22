// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useMemo, useRef, useState } from "react";
import {
  ActionIcon,
  Alert,
  Anchor,
  Badge,
  Button,
  Card,
  Checkbox,
  Code,
  CopyButton,
  Group,
  Loader,
  NumberInput,
  Radio,
  ScrollArea,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Stepper,
  Switch,
  Table,
  Text,
  TextInput,
  Textarea,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconArrowLeft, IconCheck, IconCopy, IconDeviceFloppy, IconPlus, IconSearch, IconTrash } from "@tabler/icons-react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ApiError, eventsApi, formatDate, levelLabels, rulesApi, type EventRow } from "../api";
import { useAuth } from "../auth";
import { maxPicks, setPicks, togglePick, usePicks } from "../corrPicks";
import {
  buildSteps,
  buildYAML,
  defaultChoice,
  defaultFields,
  eventLabel,
  keyable,
  keyCandidates,
  selectionOf,
  spanMs,
  suggestType,
  suggestWindow,
  typeLabels,
  uuid,
  validate,
  valueFields,
  windows,
  type Choice,
  type CorrType,
  type KeyCandidate,
  type WizEvent,
  type WizardState,
} from "../corrWizard";
import RuleTester from "./RuleTester";

function msg(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

function fmtSpan(ms: number): string {
  if (ms < 60_000) return `${Math.round(ms / 1000)} s`;
  if (ms < 3600_000) return `${Math.round(ms / 60_000)} min`;
  return `${(ms / 3600_000).toFixed(1).replace(".0", "")} h`;
}

const searchRanges: Record<string, number> = { "1h": 3600e3, "24h": 24 * 3600e3, "7d": 7 * 24 * 3600e3 };

// Wyszukiwanie zdarzeń do kreatora (bez wychodzenia ze strony).
function PickSearch() {
  const picks = usePicks();
  const [q, setQ] = useState("");
  const [range, setRange] = useState("24h");
  const [rows, setRows] = useState<EventRow[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const run = async () => {
    setBusy(true);
    setErr("");
    try {
      const now = Date.now();
      const r = await eventsApi.search({
        q,
        from: new Date(now - searchRanges[range]).toISOString().replace(/\.\d+Z$/, "Z"),
        to: new Date(now).toISOString().replace(/\.\d+Z$/, "Z"),
      });
      setRows(r.events.slice(0, 50));
    } catch (e) {
      setErr(msg(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Stack gap="xs">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void run();
        }}
      >
        <Group gap="xs" wrap="nowrap">
          <TextInput
            style={{ flex: 1 }}
            placeholder='np. code:4720 albo user:jan albo action:login outcome:failure'
            leftSection={<IconSearch size={16} />}
            value={q}
            onChange={(e) => setQ(e.currentTarget.value)}
            styles={{ input: { fontFamily: "var(--mantine-font-family-monospace)" } }}
          />
          <SegmentedControl
            size="xs"
            value={range}
            onChange={setRange}
            data={[
              { value: "1h", label: "1 h" },
              { value: "24h", label: "24 h" },
              { value: "7d", label: "7 dni" },
            ]}
          />
          <Button type="submit" loading={busy}>
            Szukaj
          </Button>
        </Group>
      </form>
      {err && <Alert color="red">{err}</Alert>}
      {rows.length > 0 && (
        <ScrollArea.Autosize mah={320}>
          <Table fz="xs" verticalSpacing={2} highlightOnHover>
            <Table.Tbody>
              {rows.map((r) => {
                const on = picks.some((p) => p.id === r.event_id);
                return (
                  <Table.Tr key={r.event_id}>
                    <Table.Td w={36}>
                      <ActionIcon
                        size="sm"
                        variant={on ? "filled" : "light"}
                        disabled={!on && picks.length >= maxPicks}
                        aria-label={on ? "usuń z przykładów" : "dodaj do przykładów"}
                        onClick={() =>
                          togglePick({
                            id: r.event_id,
                            ts: r.timestamp,
                            label: `${r.code || r.action || r.dataset} · ${r.host}${r.user ? ` · ${r.user}` : ""}`,
                          })
                        }
                      >
                        {on ? <IconCheck size={14} /> : <IconPlus size={14} />}
                      </ActionIcon>
                    </Table.Td>
                    <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(r.timestamp)}</Table.Td>
                    <Table.Td>{r.code || r.action}</Table.Td>
                    <Table.Td>{r.host}</Table.Td>
                    <Table.Td>{r.user}</Table.Td>
                    <Table.Td>
                      <Text size="xs" c="dimmed" lineClamp={1}>
                        {r.process || r.message}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </ScrollArea.Autosize>
      )}
    </Stack>
  );
}

// Wybór reguły bazowej dla przykładowego zdarzenia.
function EventCard({
  e,
  choice,
  step,
  onChange,
}: {
  e: WizEvent;
  choice: Choice;
  step: number;
  onChange: (c: Choice) => void;
}) {
  const fields = useMemo(() => {
    const std = ["EventID", "event.action", "event.outcome", "event.provider", "Channel"];
    return Object.entries(e.fields).sort(([a], [b]) => {
      const ia = std.indexOf(a);
      const ib = std.indexOf(b);
      if (ia >= 0 || ib >= 0) return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
      return a.localeCompare(b);
    });
  }, [e]);
  const value = choice.kind === "rule" ? choice.id : "__new";
  return (
    <Card withBorder padding="sm">
      <Stack gap={6}>
        <Group justify="space-between" wrap="nowrap">
          <Group gap="xs">
            <Badge>krok {step}</Badge>
            <Text size="sm" fw={500}>
              {eventLabel(e)}
            </Text>
            <Text size="xs" c="dimmed">
              {formatDate(e.timestamp)} · {e.host}
              {e.user ? ` · ${e.user}` : ""}
            </Text>
          </Group>
        </Group>
        {e.message && (
          <Text size="xs" c="dimmed" lineClamp={2}>
            {e.message}
          </Text>
        )}
        <Select
          label="Reguła bazowa"
          allowDeselect={false}
          value={value}
          onChange={(v) => {
            if (!v) return;
            if (v === "__new") onChange({ kind: "new", fields: defaultFields(e) });
            else onChange({ kind: "rule", id: v });
          }}
          data={[
            ...e.rules.map((r) => ({
              value: r.id,
              label: `${r.title}${r.threshold ? " (progowa – nie może być bazą)" : ""}`,
              disabled: r.threshold,
            })),
            { value: "__new", label: "Nowa reguła z pól tego zdarzenia" },
          ]}
          description={
            e.rules.length === 0
              ? "żadna wdrożona reguła nie pasuje do tego zdarzenia – kreator utworzy regułę bazową"
              : `pasujące wdrożone reguły: ${e.rules.length}`
          }
        />
        {choice.kind === "new" && (
          <Stack gap={4}>
            <Text size="xs" c="dimmed">
              Zaznacz pola, które muszą się zgadzać, żeby zdarzenie było tym krokiem (zwykle rodzaj zdarzenia, np. EventID, akcja,
              wynik – nie konto ani adres, bo te łączy klucz korelacji).
              {!e.product && " Źródło bez odpowiednika w Sigmie – reguła wybierze zdarzenia polem event.dataset."}
            </Text>
            <ScrollArea.Autosize mah={220}>
              <Table fz="xs" verticalSpacing={1}>
                <Table.Tbody>
                  {fields.map(([f, v]) => (
                    <Table.Tr key={f}>
                      <Table.Td w={30}>
                        <Checkbox
                          size="xs"
                          checked={choice.fields.includes(f)}
                          onChange={(ev) =>
                            onChange({
                              kind: "new",
                              fields: ev.currentTarget.checked ? [...choice.fields, f] : choice.fields.filter((x) => x !== f),
                            })
                          }
                          aria-label={f}
                        />
                      </Table.Td>
                      <Table.Td style={{ fontFamily: "monospace", whiteSpace: "nowrap" }}>{f}</Table.Td>
                      <Table.Td style={{ wordBreak: "break-all" }}>{v.length > 160 ? v.slice(0, 159) + "…" : v}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </ScrollArea.Autosize>
          </Stack>
        )}
      </Stack>
    </Card>
  );
}

function keyLabel(k: KeyCandidate, steps: number): string {
  const same = k.fields.every((f) => f === k.fields[0]);
  if (same || steps === 1) return `${k.fields[0]} (np. ${k.value})`;
  return `${k.name}: ${k.fields.map((f, i) => `${f} w kroku ${i + 1}`).join(" = ")} (np. ${k.value})`;
}

// Edycja zapisanej reguły z panelu: tylko YAML, test i zapis.
function EditPanelRule({ id }: { id: string }) {
  const { can } = useAuth();
  const navigate = useNavigate();
  const [source, setSource] = useState<string | null>(null);
  const [edited, setEdited] = useState("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    rulesApi
      .panelRule(id)
      .then((r) => {
        setSource(r.rule.source);
        setEdited(r.rule.source);
      })
      .catch((e) => setErr(msg(e)));
  }, [id]);
  const save = async () => {
    setBusy(true);
    try {
      const r = await rulesApi.savePanelRule(id, edited, note);
      notifications.show({ color: "green", message: r.message });
      navigate("/rules");
    } catch (e) {
      notifications.show({ color: "red", message: msg(e) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Stack>
      <Group>
        <Anchor component={Link} to="/rules" size="sm">
          <IconArrowLeft size={14} /> Reguły detekcji
        </Anchor>
      </Group>
      <Title order={2}>Edycja reguły z panelu</Title>
      {err && <Alert color="red">{err}</Alert>}
      {source === null && !err && <Loader />}
      {source !== null && (
        <>
          <RuleTester
            initial={source}
            onChange={setEdited}
            note={
              <Text size="xs" c="dimmed">
                Reguła korelacyjna z regułami bazowymi (dokumenty rozdzielone <Code>---</Code>). Id korelacji musi zostać {id}.
              </Text>
            }
          />
          {can("rules", "write") && (
            <Group align="flex-end">
              <TextInput style={{ flex: 1 }} label="Opis zmiany (audyt)" value={note} onChange={(e) => setNote(e.currentTarget.value)} />
              <Button leftSection={<IconDeviceFloppy size={16} />} loading={busy} onClick={() => void save()}>
                Zapisz
              </Button>
            </Group>
          )}
        </>
      )}
    </Stack>
  );
}

export default function CorrelationWizard() {
  const [params] = useSearchParams();
  const edit = params.get("edit");
  if (edit) return <EditPanelRule id={edit} />;
  return <Wizard />;
}

function Wizard() {
  const { can } = useAuth();
  const admin = can("rules", "write");
  const navigate = useNavigate();
  const picks = usePicks();
  const [active, setActive] = useState(0);
  const [events, setEvents] = useState<WizEvent[]>([]);
  const [missing, setMissing] = useState(0);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [choices, setChoices] = useState<Record<string, Choice>>({});
  const [corrId] = useState(uuid);
  const baseIds = useRef<Record<string, { id: string; name: string }>>({});
  const [title, setTitle] = useState("");
  const [level, setLevel] = useState("high");
  const [description, setDescription] = useState("");
  const [instructions, setInstructions] = useState("");
  const [type, setType] = useState<CorrType>("temporal_ordered");
  const [count, setCount] = useState<number>(2);
  const [field, setField] = useState("");
  const [windowV, setWindowV] = useState("15m");
  const [keyIdx, setKeyIdx] = useState<string>("0");
  const [generate, setGenerate] = useState(true);
  const [edited, setEdited] = useState<string | null>(null);
  const [rev, setRev] = useState(0);
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);

  const steps = useMemo(() => buildSteps(events, choices), [events, choices]);
  const keys = useMemo(() => keyCandidates(steps), [steps]);
  const key = keyIdx === "none" ? null : (keys[Number(keyIdx)] ?? null);
  const vfields = useMemo(() => valueFields(steps[0]), [steps]);
  const allFields = useMemo(() => {
    const s = new Set<string>();
    for (const e of events) for (const [f, v] of Object.entries(e.fields)) if (keyable(f, v)) s.add(f);
    return [...s].sort();
  }, [events]);
  const usesExisting = steps.some((s) => s.choice.kind === "rule");

  // Nowe reguły bazowe – stałe id między kolejnymi złożeniami YAML.
  for (const s of steps) {
    if (s.choice.kind === "new" && !baseIds.current[s.key]) {
      baseIds.current[s.key] = { id: uuid(), name: `corr_${corrId.slice(0, 8)}_${Object.keys(baseIds.current).length + 1}` };
    }
  }

  const state: WizardState = {
    title,
    id: corrId,
    level,
    description,
    instructions,
    type,
    count,
    field,
    window: windowV,
    key,
    generate,
    baseIds: baseIds.current,
  };
  const problem = validate(state, steps);
  const yaml = problem ? "" : buildYAML(state, steps);

  const loadEvents = async () => {
    setLoading(true);
    setErr("");
    try {
      const r = await rulesApi.wizardEvents(picks.map((p) => ({ id: p.id, ts: p.ts })));
      setEvents(r.events);
      setMissing(r.missing);
      const ch: Record<string, Choice> = {};
      for (const e of r.events) ch[e.event_id] = choices[e.event_id] ?? defaultChoice(e);
      setChoices(ch);
      setActive(1);
    } catch (e) {
      setErr(msg(e));
    } finally {
      setLoading(false);
    }
  };

  // Podpowiedzi przy przejściu do warunku.
  const toCondition = () => {
    setType(suggestType(steps));
    setWindowV(suggestWindow(events));
    setCount(Math.max(2, steps.length === 1 ? steps[0].events.length : 2));
    setField(vfields[0]?.field ?? "");
    setKeyIdx(keys.length ? "0" : "none");
    setGenerate(usesExisting);
    if (!title) {
      setTitle(steps.length > 1 ? steps.map((s) => s.title.replace(/\s*\(\d+\)$/, "")).join(", potem ") : `Seria: ${steps[0]?.title ?? ""}`);
    }
    setActive(2);
  };

  const save = async () => {
    setSaving(true);
    try {
      const r = await rulesApi.savePanelRule(corrId, edited ?? yaml, note);
      notifications.show({ color: "green", message: r.message });
      setPicks([]);
      navigate("/rules");
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof ApiError ? e.message : msg(e) });
    } finally {
      setSaving(false);
    }
  };

  const span = spanMs(events);
  const temporal = type === "temporal" || type === "temporal_ordered";

  return (
    <Stack>
      <Group>
        <Anchor component={Link} to="/rules" size="sm">
          <IconArrowLeft size={14} /> Reguły detekcji
        </Anchor>
      </Group>
      <div>
        <Title order={2}>Kreator korelacji</Title>
        <Text c="dimmed" size="sm" maw={860}>
          Wskaż przykładowe zdarzenia, które razem świadczą o ataku (np. utworzenie konta, a potem dodanie go do grupy
          administratorów). Kreator zaproponuje kroki, wspólny klucz i okno czasu, złoży regułę Sigma Correlation i pozwoli
          sprawdzić ją na historii przed zapisem.
        </Text>
      </div>
      {err && <Alert color="red">{err}</Alert>}

      <Stepper active={active} onStepClick={(i) => i < active && setActive(i)} size="sm">
        <Stepper.Step label="Zdarzenia" description="przykłady">
          <Stack gap="sm" mt="sm">
            <Card withBorder padding="sm">
              <Stack gap="xs">
                <Group justify="space-between">
                  <Text fw={500}>
                    Wybrane zdarzenia ({picks.length}/{maxPicks})
                  </Text>
                  {picks.length > 0 && (
                    <Button size="xs" variant="subtle" color="gray" onClick={() => setPicks([])}>
                      wyczyść
                    </Button>
                  )}
                </Group>
                {picks.length === 0 && (
                  <Text size="sm" c="dimmed">
                    Brak. Dodaj zdarzenia wyszukiwarką niżej albo w Mímirze (szczegóły zdarzenia → „Dodaj do kreatora korelacji”).
                    Dla serii jednego rodzaju (np. nieudane logowania z wielu adresów) wystarczy kilka przykładów tego samego
                    zdarzenia.
                  </Text>
                )}
                {[...picks]
                  .sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts))
                  .map((p) => (
                    <Group key={p.id} gap="xs" wrap="nowrap">
                      <ActionIcon size="sm" variant="subtle" color="red" onClick={() => togglePick(p)} aria-label="usuń">
                        <IconTrash size={14} />
                      </ActionIcon>
                      <Text size="sm" style={{ whiteSpace: "nowrap" }}>
                        {formatDate(p.ts)}
                      </Text>
                      <Text size="sm" c="dimmed" lineClamp={1}>
                        {p.label}
                      </Text>
                    </Group>
                  ))}
              </Stack>
            </Card>
            <PickSearch />
            <Group>
              <Button disabled={picks.length === 0} loading={loading} onClick={() => void loadEvents()}>
                Dalej: kroki
              </Button>
            </Group>
          </Stack>
        </Stepper.Step>

        <Stepper.Step label="Kroki" description="reguły bazowe">
          <Stack gap="sm" mt="sm">
            {missing > 0 && (
              <Alert color="orange">
                {missing} z wybranych zdarzeń nie ma już w bazie (retencja) – pominięte.
              </Alert>
            )}
            <Text size="sm" c="dimmed">
              Każde zdarzenie to krok korelacji: istniejąca reguła, która do niego pasuje, albo nowa reguła bazowa z wybranych pól.
              Zdarzenia z tym samym wyborem tworzą jeden krok. Kolejność kroków – według czasu pierwszego przykładu.
            </Text>
            {[...events]
              .sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))
              .map((e) => (
                <EventCard
                  key={e.event_id}
                  e={e}
                  choice={choices[e.event_id] ?? defaultChoice(e)}
                  step={steps.findIndex((s) => s.events.includes(e)) + 1}
                  onChange={(c) => setChoices({ ...choices, [e.event_id]: c })}
                />
              ))}
            <Card withBorder padding="sm" bg="var(--mantine-color-default-hover)">
              <Text size="sm" fw={500}>
                Kroki ({steps.length})
              </Text>
              {steps.map((s, i) => (
                <Text size="sm" key={s.key}>
                  {i + 1}. {s.title} – {s.choice.kind === "rule" ? "istniejąca reguła" : "nowa reguła bazowa"}, przykładów:{" "}
                  {s.events.length}
                  {s.choice.kind === "new" && (
                    <Text span size="xs" c="dimmed">
                      {" "}
                      ({selectionOf(s.events[0], s.choice.fields)
                        .map(([k, v]) => `${k}=${v}`)
                        .join(", ") || "brak pól!"}
                      )
                    </Text>
                  )}
                </Text>
              ))}
            </Card>
            <Group>
              <Button variant="default" onClick={() => setActive(0)}>
                Wstecz
              </Button>
              <Button onClick={toCondition} disabled={steps.length === 0}>
                Dalej: warunek
              </Button>
            </Group>
          </Stack>
        </Stepper.Step>

        <Stepper.Step label="Warunek" description="klucz, typ, okno">
          <Stack gap="sm" mt="sm">
            <Radio.Group
              label="Co łączy zdarzenia (klucz)"
              description={
                steps.length > 1
                  ? "Wartość, która występuje we wszystkich krokach – kreator znalazł ją w przykładach. Różne nazwy pól w krokach to aliasy."
                  : "Wartość wspólna wszystkim przykładom – liczone są zdarzenia z tą samą wartością."
              }
              value={keyIdx}
              onChange={setKeyIdx}
            >
              <Stack gap={4} mt={4}>
                {keys.map((k, i) => (
                  <Radio key={i} value={String(i)} label={keyLabel(k, steps.length)} />
                ))}
                <Radio value="none" label="bez klucza – wszystkie zdarzenia razem (rzadko ma sens)" />
                {keys.length === 0 && (
                  <Text size="xs" c="orange">
                    Przykłady nie mają wspólnej wartości. Dodaj zdarzenia dotyczące tego samego konta, komputera albo adresu.
                  </Text>
                )}
              </Stack>
            </Radio.Group>
            <SimpleGrid cols={{ base: 1, sm: 3 }}>
              <Select
                label="Typ"
                allowDeselect={false}
                value={type}
                onChange={(v) => v && setType(v as CorrType)}
                data={(Object.keys(typeLabels) as CorrType[]).map((t) => ({
                  value: t,
                  label: typeLabels[t],
                  disabled: (t === "temporal" || t === "temporal_ordered") && steps.length < 2,
                }))}
              />
              <Select
                label="Okno czasu"
                allowDeselect={false}
                value={windowV}
                onChange={(v) => v && setWindowV(v)}
                data={windows.map((w) => ({ value: w, label: w === suggestWindow(events) ? `${w} (podpowiedź)` : w }))}
                description={span > 0 ? `przykłady rozłożone na ${fmtSpan(span)}` : undefined}
              />
              {!temporal && (
                <NumberInput
                  label={type === "value_count" ? "Co najmniej różnych wartości" : "Co najmniej zdarzeń"}
                  min={2}
                  max={10000}
                  value={count}
                  onChange={(v) => setCount(typeof v === "number" ? v : parseInt(v, 10) || 2)}
                />
              )}
            </SimpleGrid>
            {type === "value_count" && (
              <Select
                label="Pole, którego różne wartości liczyć"
                searchable
                value={field || null}
                onChange={(v) => setField(v ?? "")}
                data={[
                  ...vfields.map((f) => ({ value: f.field, label: `${f.field} (${f.values} różnych w przykładach)` })),
                  ...allFields.filter((f) => !vfields.some((x) => x.field === f)).map((f) => ({ value: f, label: f })),
                ]}
              />
            )}
            {problem && <Alert color="orange">{problem}</Alert>}
            <Group>
              <Button variant="default" onClick={() => setActive(1)}>
                Wstecz
              </Button>
              <Button onClick={() => setActive(3)} disabled={!!problem && problem !== "podaj tytuł"}>
                Dalej: opis i test
              </Button>
            </Group>
          </Stack>
        </Stepper.Step>

        <Stepper.Step label="Opis i test" description="zapis">
          <Stack gap="sm" mt="sm">
            <SimpleGrid cols={{ base: 1, sm: 3 }}>
              <TextInput
                label="Tytuł"
                style={{ gridColumn: "span 2" }}
                value={title}
                onChange={(e) => {
                  setTitle(e.currentTarget.value);
                  setEdited(null);
                }}
              />
              <Select
                label="Poziom"
                allowDeselect={false}
                value={level}
                onChange={(v) => {
                  if (v) setLevel(v);
                  setEdited(null);
                }}
                data={Object.entries(levelLabels).map(([value, l]) => ({ value, label: l.label }))}
              />
            </SimpleGrid>
            <Textarea
              label="Opis"
              description="co wykrywa i dlaczego to groźne"
              autosize
              minRows={2}
              value={description}
              onChange={(e) => {
                setDescription(e.currentTarget.value);
                setEdited(null);
              }}
            />
            <Textarea
              label="Instrukcja dla analityka"
              description="pola ostatniego zdarzenia ({{TargetUserName}}) oraz {{count}}, {{window}}, {{rules}}, {{key}}"
              autosize
              minRows={2}
              value={instructions}
              onChange={(e) => {
                setInstructions(e.currentTarget.value);
                setEdited(null);
              }}
            />
            <Switch
              checked={generate}
              onChange={(e) => {
                setGenerate(e.currentTarget.checked);
                setEdited(null);
              }}
              label="Reguły bazowe nadal tworzą własne alerty (generate: true)"
              description="wyłączone – reguły bazowe tylko zasilają korelację"
            />
            {usesExisting && !generate && (
              <Alert color="orange">
                Korelacja używa wdrożonych reguł. Bez „generate” te reguły przestaną same tworzyć alerty (o ile żadna inna korelacja
                ich nie potrzebuje) – zwykle tego nie chcesz.
              </Alert>
            )}
            {problem ? (
              <Alert color="orange">{problem}</Alert>
            ) : (
              <>
                {edited !== null && (
                  <Alert color="blue">
                    YAML zmieniony ręcznie – zmiany pól wyżej go nadpiszą.{" "}
                    <Anchor
                      component="button"
                      size="sm"
                      onClick={() => {
                        setEdited(null);
                        setRev((r) => r + 1);
                      }}
                    >
                      Wróć do wygenerowanego
                    </Anchor>
                  </Alert>
                )}
                <RuleTester
                  key={rev}
                  initial={yaml}
                  onChange={setEdited}
                  note={
                    <Text size="xs" c="dimmed">
                      Wygenerowana reguła (YAML) – możesz ją poprawić ręcznie. „Przetestuj” liczy alerty, które powstałyby na
                      zdarzeniach z wybranego okresu; nic nie jest zapisywane.
                    </Text>
                  }
                />
                {admin ? (
                  <Group align="flex-end">
                    <TextInput
                      style={{ flex: 1 }}
                      label="Opis zmiany (audyt)"
                      value={note}
                      onChange={(e) => setNote(e.currentTarget.value)}
                    />
                    <Button leftSection={<IconDeviceFloppy size={16} />} loading={saving} onClick={() => void save()}>
                      Zapisz regułę
                    </Button>
                  </Group>
                ) : (
                  <Group>
                    <Text size="sm" c="dimmed">
                      Zapis wymaga roli administratora – skopiuj regułę i przekaż ją administratorowi.
                    </Text>
                    <CopyButton value={edited ?? yaml}>
                      {({ copied, copy }) => (
                        <Tooltip label={copied ? "skopiowano" : "kopiuj YAML"}>
                          <ActionIcon variant="light" onClick={copy}>
                            {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                          </ActionIcon>
                        </Tooltip>
                      )}
                    </CopyButton>
                  </Group>
                )}
              </>
            )}
            <Group>
              <Button variant="default" onClick={() => setActive(2)}>
                Wstecz
              </Button>
            </Group>
          </Stack>
        </Stepper.Step>
      </Stepper>
    </Stack>
  );
}
