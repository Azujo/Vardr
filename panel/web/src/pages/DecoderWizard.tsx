import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Alert as MAlert,
  Badge,
  Button,
  Card,
  Checkbox,
  Code,
  Group,
  NumberInput,
  ScrollArea,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Table,
  TagsInput,
  Text,
  TextInput,
  Textarea,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconDownload, IconEdit, IconRefresh, IconTrash, IconWand } from "@tabler/icons-react";
import { decodersApi, type DecodeResult, type DecoderTestResponse } from "../api";
import {
  LABELS,
  LAYOUTS,
  buildRegex,
  buildYAML,
  checkRegex,
  detectMode,
  flattenJSON,
  groupName,
  guessLayout,
  labelDef,
  parseKV,
  patternRegexes,
  slug,
  type LabelKey,
  type Layout,
  type Mode,
  type PatternDef,
  type Span,
} from "../decoderWizard";

// Kreator dekoderów: zaznaczasz w przykładowej wiadomości fragmenty
// i nadajesz im etykiety (kliknięciem albo przeciągnięciem etykiety na
// zaznaczenie), kreator buduje definicję dekodera i od razu sprawdza ją
// na wszystkich próbkach. Wynik to zwykły dekoder – można go zapisać albo
// dopracować w edytorze.

const fieldLabels = LABELS.filter((l) => l.key !== "match" && l.key !== "any");
const markColor = (k: LabelKey) => `var(--mantine-color-${labelDef(k).color}-${k === "match" ? 3 : 2})`;

interface Props {
  initialSamples: string[];
  initialPeer?: string;
  admin: boolean;
  samplesAvailable: boolean;
  onEdit: (yaml: string) => void;
  onSaved: () => void;
}

export default function DecoderWizard({ initialSamples, initialPeer, admin, samplesAvailable, onEdit, onSaved }: Props) {
  const [samplesText, setSamplesText] = useState(initialSamples.join("\n"));
  const [peer, setPeer] = useState(initialPeer ?? "");
  const [parsed, setParsed] = useState<DecodeResult[]>([]);
  const [sel, setSel] = useState(0);
  const [mode, setMode] = useState<Mode>("regex");
  const [patterns, setPatterns] = useState<PatternDef[]>([]);
  const [keyLabels, setKeyLabels] = useState<Record<string, { key: LabelKey; custom?: string }>>({});
  const [requiredKeys, setRequiredKeys] = useState<string[]>([]);
  const [pending, setPending] = useState<{ start: number; end: number } | null>(null);
  const [customName, setCustomName] = useState("");
  const [meta, setMeta] = useState({ id: "", title: "", dataset: "", priority: 60 });
  const [match, setMatch] = useState({ app: false, host: false, peer: false });
  const [byPatterns, setByPatterns] = useState(true);
  const [existing, setExisting] = useState<Record<string, string>>({}); // id → nazwa
  const [replace, setReplace] = useState(false);
  const [timeLayout, setTimeLayout] = useState("");
  const [timeZone, setTimeZone] = useState("");
  const [outSuccess, setOutSuccess] = useState<string[]>([]);
  const [outFailure, setOutFailure] = useState<string[]>([]);
  const [test, setTest] = useState<DecoderTestResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);

  const samples = useMemo(() => samplesText.split("\n").filter((l) => l.trim() !== ""), [samplesText]);
  const raws = useMemo(() => parsed.map((r) => r.raw), [parsed]);
  const stale = parsed.length > 0 && raws.join("\n") !== samples.join("\n");
  const cur = parsed[sel];

  // Istniejące dekodery – id nowego nie może po cichu zastąpić wbudowanego.
  useEffect(() => {
    decodersApi
      .list()
      .then((r) => setExisting(Object.fromEntries(r.decoders.map((d) => [d.id, d.title]))))
      .catch(() => {});
  }, []);
  const msg = cur?.header.message ?? "";

  // Rozbiór nagłówków próbek (test zestawu działających dekoderów, bez definicji).
  const parse = useCallback(async () => {
    if (samples.length === 0) {
      setParsed([]);
      return;
    }
    setLoading(true);
    try {
      const r = await decodersApi.test("", samples, peer.trim());
      const res = r.results ?? [];
      setParsed(res);
      setSel(0);
      setPatterns([]);
      setPending(null);
      const first = res[0];
      if (first) {
        setMode(detectMode(first.header.message));
        const name = first.header.app || first.header.host || "urzadzenie";
        setMeta((m) => ({
          id: m.id || slug(name) + "-kreator",
          title: m.title || `${name} – dekoder z kreatora`,
          dataset: m.dataset || `${slug(name).replace(/-/g, "_")}.log`,
          priority: m.priority,
        }));
        setMatch({ app: !!first.header.app, host: !first.header.app && !!first.header.host, peer: false });
      }
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setLoading(false);
    }
  }, [samples, peer]);
  useEffect(() => {
    if (initialSamples.length) void parse();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadUnrecognized = async () => {
    setLoading(true);
    try {
      const r = await decodersApi.samples({ peer: peer.trim(), hours: 168, limit: 100 });
      if (r.samples.length === 0) notifications.show({ color: "gray", message: "Brak nierozpoznanych wiadomości z ostatnich 7 dni" });
      setSamplesText(r.samples.map((s) => s.raw).join("\n"));
      const peers = new Set(r.samples.map((s) => s.peer));
      if (!peer.trim() && peers.size === 1) setPeer([...peers][0]);
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setLoading(false);
    }
  };

  // ---- etykiety w trybie tekstowym ----
  const pattern = patterns.find((p) => p.sampleIndex === sel);
  const spans = pattern?.spans ?? [];
  const setPattern = (f: (p: PatternDef) => PatternDef | null) =>
    setPatterns((ps) => {
      const old = ps.find((p) => p.sampleIndex === sel) ?? { sampleIndex: sel, msg, spans: [] };
      const next = f(old);
      const rest = ps.filter((p) => p.sampleIndex !== sel);
      return next && (next.spans.length > 0 || next.action || next.outcome) ? [...rest, next] : rest;
    });

  const offsetIn = (node: Node, off: number): number => {
    const box = boxRef.current!;
    const r = document.createRange();
    r.setStart(box, 0);
    r.setEnd(node, off);
    return r.toString().length;
  };
  const onMouseUp = () => {
    const s = window.getSelection();
    if (!s || s.rangeCount === 0 || s.isCollapsed || !boxRef.current?.contains(s.anchorNode)) return;
    const a = offsetIn(s.anchorNode!, s.anchorOffset);
    const b = offsetIn(s.focusNode!, s.focusOffset);
    let start = Math.min(a, b);
    let end = Math.max(a, b);
    while (start < end && /\s/.test(msg[start])) start++;
    while (end > start && /\s/.test(msg[end - 1])) end--;
    if (end > start) setPending({ start, end });
  };
  // wordAt: słowo (ciąg bez odstępów) pod wskazanym punktem wiadomości.
  const wordAt = (x: number, y: number): { start: number; end: number } | null => {
    const doc = document as Document & { caretPositionFromPoint?: (x: number, y: number) => { offsetNode: Node; offset: number } | null };
    let node: Node | null = null;
    let off = 0;
    if (doc.caretPositionFromPoint) {
      const p = doc.caretPositionFromPoint(x, y);
      if (p) [node, off] = [p.offsetNode, p.offset];
    } else if (document.caretRangeFromPoint) {
      const r = document.caretRangeFromPoint(x, y);
      if (r) [node, off] = [r.startContainer, r.startOffset];
    }
    if (!node || !boxRef.current?.contains(node)) return null;
    const at = offsetIn(node, off);
    let start = at;
    let end = at;
    while (start > 0 && !/\s/.test(msg[start - 1])) start--;
    while (end < msg.length && !/\s/.test(msg[end])) end++;
    return end > start ? { start, end } : null;
  };
  const applyLabel = (key: LabelKey, target: { start: number; end: number } | null = pending) => {
    const pending = target;
    if (!pending) {
      notifications.show({ color: "gray", message: "Najpierw zaznacz fragment wiadomości myszą (albo upuść etykietę na słowie)" });
      return;
    }
    if (key === "custom" && !/^[a-z][a-z0-9_.]{1,40}$/.test(customName.trim())) {
      notifications.show({ color: "orange", message: "Własne pole: wpisz nazwę (małe litery, cyfry, kropki), np. vpn.tunnel" });
      return;
    }
    const overl = spans.some((x) => pending.start < x.end && x.start < pending.end);
    if (overl) {
      notifications.show({ color: "orange", message: "Fragment nachodzi na już oznaczony – kliknij stary, aby go usunąć" });
      return;
    }
    const span: Span = { ...pending, key, custom: key === "custom" ? customName.trim() : undefined };
    setPattern((p) => ({ ...p, msg, spans: [...p.spans.filter((x) => key === "time" || x.key !== key || key === "match" || key === "any"), span] }));
    if (key === "time" && !timeLayout) {
      const v = msg.slice(pending.start, pending.end);
      const g = guessLayout(v);
      if (g && !g.noYear) setTimeLayout(g.value);
    }
    setPending(null);
    window.getSelection()?.removeAllRanges();
  };
  const removeSpan = (s: Span) => setPattern((p) => ({ ...p, spans: p.spans.filter((x) => x !== s) }));

  // Segmenty wiadomości do wyświetlenia (oznaczone, zaznaczone, zwykłe).
  const segments = useMemo(() => {
    const marks: { start: number; end: number; span?: Span; pending?: boolean }[] = spans.map((s) => ({ start: s.start, end: s.end, span: s }));
    if (pending) marks.push({ ...pending, pending: true });
    marks.sort((a, b) => a.start - b.start);
    const out: { text: string; span?: Span; pending?: boolean }[] = [];
    let pos = 0;
    for (const m of marks) {
      if (m.start < pos) continue;
      if (m.start > pos) out.push({ text: msg.slice(pos, m.start) });
      out.push({ text: msg.slice(m.start, m.end), span: m.span, pending: m.pending });
      pos = m.end;
    }
    if (pos < msg.length) out.push({ text: msg.slice(pos) });
    return out;
  }, [msg, spans, pending]);

  // ---- tryb kv / json ----
  const pairs = useMemo(() => (mode === "kv" ? parseKV(msg) : mode === "json" ? flattenJSON(msg) : []), [mode, msg]);

  // ---- definicja ----
  const hasTime = mode === "regex" ? patterns.some((p) => p.spans.some((s) => s.key === "time")) : Object.values(keyLabels).some((v) => v.key === "time");
  const hasOutcome =
    mode === "regex" ? patterns.some((p) => p.spans.some((s) => s.key === "outcome")) : Object.values(keyLabels).some((v) => v.key === "outcome");
  const timeSample = useMemo(() => {
    if (mode === "regex") {
      const p = patterns.find((x) => x.spans.some((s) => s.key === "time"));
      return p
        ? p.spans
            .filter((s) => s.key === "time")
            .sort((a, b) => a.start - b.start)
            .map((s) => p.msg.slice(s.start, s.end))
            .join(" ")
        : "";
    }
    const kv = Object.fromEntries(pairs);
    return Object.entries(keyLabels)
      .filter(([, v]) => v.key === "time")
      .map(([k]) => kv[k] ?? "")
      .join(" ");
  }, [mode, patterns, keyLabels, pairs]);
  useEffect(() => {
    if (mode !== "regex" && timeSample && !timeLayout) {
      const g = guessLayout(timeSample);
      if (g) setTimeLayout(g.value);
    }
  }, [mode, timeSample, timeLayout]);

  const built = useMemo(() => {
    if (!cur) return { yaml: "", error: "wczytaj próbki" };
    if (!/^[a-z0-9][a-z0-9._-]{1,63}$/.test(meta.id)) return { yaml: "", error: "id: małe litery, cyfry, . _ - (2–64 znaki)" };
    if (existing[meta.id] && !replace)
      return { yaml: "", error: `id „${meta.id}” ma już dekoder „${existing[meta.id]}” – zmień id albo zaznacz „zastąp istniejący”` };
    if (!/^[a-z0-9][a-z0-9._-]*$/.test(meta.dataset) || meta.dataset.startsWith("windows.") || meta.dataset === "syslog.generic")
      return { yaml: "", error: "zbiór danych: małe litery, cyfry, . _ - (bez windows.* i syslog.generic)" };
    const contains = [
      ...new Set(
        mode === "regex"
          ? patterns.flatMap((p) => p.spans.filter((s) => s.key === "match").map((s) => p.msg.slice(s.start, s.end)))
          : requiredKeys.map((k) => (mode === "kv" ? `${k}=` : `"${k.split(".").pop()}"`)),
      ),
    ];
    return buildYAML({
      id: meta.id,
      title: meta.title || meta.id,
      dataset: meta.dataset,
      priority: meta.priority,
      mode,
      matchApp: match.app ? cur.header.app : undefined,
      matchHost: match.host ? cur.header.host : undefined,
      matchPeer: match.peer ? peer.trim() : undefined,
      matchContains: contains,
      matchByPatterns: byPatterns,
      patterns,
      keyLabels,
      timeLayout: hasTime ? timeLayout : "",
      timeZone,
      outcomeSuccess: outSuccess,
      outcomeFailure: outFailure,
      samples: [], // próbki dopisuje zapis – tylko te, które ten dekoder rozpoznaje
    });
  }, [existing, replace, cur, meta, mode, match, byPatterns, peer, patterns, keyLabels, requiredKeys, hasTime, timeLayout, timeZone, outSuccess, outFailure]);

  // Wartości pola „wynik” widziane w próbkach (do przypisania udane/nieudane).
  const outcomeValues = useMemo(() => {
    const vals = new Set<string>();
    if (mode === "regex") {
      for (const p of patterns) {
        const sp = p.spans.find((x) => x.key === "outcome");
        if (!sp) continue;
        const b = patternRegexes({ patterns: [p], timeLayout })[0];
        for (const r of parsed) {
          const g = b.error ? null : checkRegex(b.regex, r.header.message);
          if (g?.result) vals.add(g.result);
        }
      }
    } else {
      const keys = Object.entries(keyLabels)
        .filter(([, v]) => v.key === "outcome")
        .map(([k]) => k);
      for (const r of parsed) {
        const kv = Object.fromEntries(mode === "kv" ? parseKV(r.header.message) : flattenJSON(r.header.message));
        for (const k of keys) if (kv[k]) vals.add(kv[k]);
      }
    }
    return [...vals].slice(0, 20);
  }, [mode, patterns, keyLabels, parsed, timeLayout]);

  // Wzorzec bieżącej wiadomości sprawdzony od razu w przeglądarce.
  const local = useMemo(() => {
    if (mode !== "regex" || !pattern) return null;
    const lay: Record<string, Layout | undefined> = {};
    const l = LAYOUTS.find((x) => x.value === timeLayout);
    for (const s of pattern.spans) if (s.key === "time") lay[groupName(s)] = l;
    const b = buildRegex(msg, pattern.spans, lay);
    return b.error ? null : { regex: b.regex, groups: checkRegex(b.regex, msg) };
  }, [mode, pattern, msg, timeLayout]);

  // Test na wszystkich próbkach (z opóźnieniem po zmianach).
  useEffect(() => {
    if (!built.yaml || raws.length === 0) {
      setTest(null);
      return;
    }
    const t = setTimeout(() => {
      decodersApi
        .test(built.yaml, raws, peer.trim())
        .then(setTest)
        .catch((e) => setTest({ ok: false, error: e instanceof Error ? e.message : String(e) }));
    }, 700);
    return () => clearTimeout(t);
  }, [built.yaml, raws, peer]);

  // Definicja do zapisu: z próbkami (do 10), które ten dekoder rozpoznaje –
  // zapis odrzuca definicję, której próbka się nie dekoduje.
  const finalYAML = () => {
    const ok = (test?.results ?? []).filter((r) => r.decoder === meta.id && r.pattern && !r.error).map((r) => r.raw);
    const extra = ok
      .slice(0, 10)
      .map((x) => `  - '${x.replace(/'/g, "''")}'`)
      .join("\n");
    return ok.length ? `${built.yaml}samples:\n${extra}\n` : built.yaml;
  };
  const save = async () => {
    setSaving(true);
    try {
      const r = await decodersApi.save(meta.id, finalYAML(), note.trim() || "utworzony kreatorem");
      notifications.show({ color: "green", message: `Rewizja ${r.revision}: ${r.message}` });
      onSaved();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setSaving(false);
    }
  };

  const sum = test?.summary;
  const regexes = useMemo(() => (mode === "regex" ? patternRegexes({ patterns, timeLayout }) : []), [mode, patterns, timeLayout]);
  const patternOf = (m: string): number[] =>
    regexes.flatMap((b, i) => (!b.error && checkRegex(b.regex, m) ? [i] : []));
  const patternNo = (i: number) => {
    const ps = patterns[i];
    return ps ? parsed.findIndex((_, k) => k === ps.sampleIndex) + 1 : 0;
  };
  const matchedBy = (i: number) => {
    const r = test?.results?.[i];
    return r ? r.decoder === meta.id && r.pattern && !r.error : false;
  };

  return (
    <Stack gap="sm">
      <Card withBorder p="sm">
        <Group justify="space-between" mb={4}>
          <Text fw={600} size="sm">
            1. Próbki ({samples.length})
          </Text>
          <Group gap="xs">
            <TextInput size="xs" placeholder="adres nadawcy" w={150} value={peer} onChange={(e) => setPeer(e.currentTarget.value)} />
            {samplesAvailable && (
              <Button size="xs" variant="default" leftSection={<IconDownload size={14} />} loading={loading} onClick={() => void loadUnrecognized()}>
                Nierozpoznane (7 dni)
              </Button>
            )}
            <Button size="xs" leftSection={<IconRefresh size={14} />} loading={loading} onClick={() => void parse()}>
              Wczytaj
            </Button>
          </Group>
        </Group>
        {stale && (
          <Text size="xs" c="orange" mb={4}>
            Próbki zmienione – kliknij „Wczytaj”, żeby kreator i sprawdzenie ich użyły.
          </Text>
        )}
        <Textarea
          autosize
          minRows={2}
          maxRows={6}
          spellCheck={false}
          styles={{ input: { fontFamily: "monospace", fontSize: 11 } }}
          placeholder="jedna wiadomość syslog w wierszu (z nagłówkiem), np. z kwarantanny albo pliku"
          value={samplesText}
          onChange={(e) => setSamplesText(e.currentTarget.value)}
        />
      </Card>

      {cur && (
        <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="sm">
          <Stack gap="sm">
            <Card withBorder p="sm">
              <Group justify="space-between" mb={6}>
                <Text fw={600} size="sm">
                  2. Oznacz pola
                </Text>
                <SegmentedControl
                  size="xs"
                  value={mode}
                  onChange={(v) => setMode(v as Mode)}
                  data={[
                    { value: "regex", label: "tekst" },
                    { value: "kv", label: "klucz=wartość" },
                    { value: "json", label: "JSON" },
                  ]}
                />
              </Group>
              <Select
                size="xs"
                label="Wiadomość"
                allowDeselect={false}
                value={String(sel)}
                onChange={(v) => {
                  setSel(Number(v));
                  setPending(null);
                }}
                data={parsed.map((r, i) => ({
                  value: String(i),
                  label: `${patterns.some((p) => p.sampleIndex === i) ? "● " : ""}${i + 1}. ${r.header.message.slice(0, 90)}`,
                }))}
              />
              <Text size="xs" c="dimmed" mt={4}>
                nagłówek: program <Code>{cur.header.app || "—"}</Code>, host <Code>{cur.header.host || "—"}</Code>, format {cur.header.format}
              </Text>

              {mode === "regex" ? (
                <Stack gap={6} mt="xs">
                  <Text size="xs" c="dimmed">
                    Zaznacz myszą fragment poniżej, potem kliknij etykietę albo przeciągnij ją na zaznaczenie. Kliknięcie oznaczonego
                    fragmentu usuwa etykietę. Każdy rodzaj wiadomości (np. logowanie udane i nieudane) oznacz osobno – kreator zrobi z
                    nich osobne wzorce.
                  </Text>
                  <Group gap={4}>
                    {LABELS.map((l) => (
                      <Tooltip key={l.key} label={l.hint ?? l.target ?? ""} disabled={!l.hint && !l.target}>
                        <Badge
                          color={l.color}
                          variant={l.key === "any" ? "outline" : "light"}
                          style={{ cursor: "grab", textTransform: "none" }}
                          draggable
                          onDragStart={(e) => e.dataTransfer.setData("text/plain", l.key)}
                          onClick={() => applyLabel(l.key)}
                        >
                          {l.label}
                        </Badge>
                      </Tooltip>
                    ))}
                    <TextInput
                      size="xs"
                      w={150}
                      placeholder="nazwa własnego pola"
                      value={customName}
                      onChange={(e) => setCustomName(e.currentTarget.value)}
                    />
                  </Group>
                  <div
                    ref={boxRef}
                    onMouseUp={onMouseUp}
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={(e) => {
                      e.preventDefault();
                      const k = e.dataTransfer.getData("text/plain") as LabelKey;
                      if (!LABELS.some((l) => l.key === k)) return;
                      // Bez zaznaczenia – słowo pod kursorem.
                      applyLabel(k, pending ?? wordAt(e.clientX, e.clientY));
                    }}
                    style={{
                      fontFamily: "monospace",
                      fontSize: 13,
                      lineHeight: 2,
                      padding: 10,
                      border: "1px solid var(--mantine-color-default-border)",
                      borderRadius: 6,
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-all",
                      userSelect: "text",
                    }}
                  >
                    {segments.map((s, i) =>
                      s.span ? (
                        <Tooltip key={i} label={`${s.span.key === "custom" ? s.span.custom : labelDef(s.span.key).label} – kliknij, aby usunąć`}>
                          <span
                            onClick={() => removeSpan(s.span!)}
                            style={{ background: markColor(s.span.key), borderRadius: 3, padding: "1px 0", cursor: "pointer", color: "black" }}
                          >
                            {s.text}
                          </span>
                        </Tooltip>
                      ) : s.pending ? (
                        <span key={i} style={{ outline: "2px dashed var(--mantine-color-blue-5)", borderRadius: 3 }}>
                          {s.text}
                        </span>
                      ) : (
                        <span key={i}>{s.text}</span>
                      ),
                    )}
                  </div>
                  {pattern && (
                    <Group gap="xs" align="flex-end">
                      <TextInput
                        size="xs"
                        label="Akcja dla tej wiadomości"
                        description="np. login, logout, config-change"
                        w={200}
                        value={pattern.action ?? ""}
                        onChange={(e) => {
                          const v = e.currentTarget.value;
                          setPattern((p) => ({ ...p, action: v }));
                        }}
                      />
                      <Select
                        size="xs"
                        label="Wynik dla tej wiadomości"
                        w={160}
                        value={pattern.outcome ?? ""}
                        onChange={(v) => setPattern((p) => ({ ...p, outcome: (v ?? "") as PatternDef["outcome"] }))}
                        data={[
                          { value: "", label: "—" },
                          { value: "success", label: "udane" },
                          { value: "failure", label: "nieudane" },
                        ]}
                      />
                      <Button size="xs" variant="subtle" color="red" leftSection={<IconTrash size={12} />} onClick={() => setPattern(() => null)}>
                        usuń wzorzec
                      </Button>
                    </Group>
                  )}
                  {local && (
                    <Text size="xs" c={local.groups ? "green" : "red"}>
                      {local.groups
                        ? "wzorzec pasuje do tej wiadomości: " +
                          Object.entries(local.groups)
                            .map(([k, v]) => `${k}=${v}`)
                            .join(", ")
                        : "wzorzec nie pasuje do tej wiadomości – sprawdź zaznaczenia"}
                    </Text>
                  )}
                </Stack>
              ) : (
                <Stack gap={4} mt="xs">
                  <Text size="xs" c="dimmed">
                    Przypisz etykiety polom wiadomości. „wymagaj” – wiadomość musi mieć to pole (rozpoznawanie).
                  </Text>
                  <ScrollArea.Autosize mah={420}>
                    <Table fz="xs" verticalSpacing={2}>
                      <Table.Tbody>
                        {pairs.map(([k, v]) => (
                          <Table.Tr key={k}>
                            <Table.Td ff="monospace">{k}</Table.Td>
                            <Table.Td maw={220} style={{ wordBreak: "break-all" }}>
                              {v}
                            </Table.Td>
                            <Table.Td w={170}>
                              <Select
                                size="xs"
                                placeholder="—"
                                clearable
                                value={keyLabels[k]?.key ?? null}
                                onChange={(val) =>
                                  setKeyLabels((m) => {
                                    const n = { ...m };
                                    if (!val) delete n[k];
                                    else n[k] = { key: val as LabelKey, custom: val === "custom" ? m[k]?.custom ?? k.toLowerCase() : undefined };
                                    return n;
                                  })
                                }
                                data={fieldLabels.map((l) => ({ value: l.key, label: l.label }))}
                              />
                              {keyLabels[k]?.key === "custom" && (
                                <TextInput
                                  size="xs"
                                  mt={2}
                                  value={keyLabels[k].custom ?? ""}
                                  onChange={(e) => {
                                    const c = e.currentTarget.value;
                                    setKeyLabels((m) => ({ ...m, [k]: { key: "custom", custom: c } }));
                                  }}
                                />
                              )}
                            </Table.Td>
                            <Table.Td>
                              <Checkbox
                                size="xs"
                                label="wymagaj"
                                checked={requiredKeys.includes(k)}
                                onChange={(e) => {
                                  const on = e.currentTarget.checked;
                                  setRequiredKeys((l) => (on ? [...l, k] : l.filter((x) => x !== k)));
                                }}
                              />
                            </Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </ScrollArea.Autosize>
                </Stack>
              )}
            </Card>
          </Stack>

          <Stack gap="sm">
            <Card withBorder p="sm">
              <Text fw={600} size="sm" mb={4}>
                3. Dekoder
              </Text>
              <Group gap="xs" align="flex-end">
                <TextInput size="xs" label="Id" w={170} value={meta.id} onChange={(e) => setMeta({ ...meta, id: e.currentTarget.value })} />
                <TextInput size="xs" label="Nazwa" style={{ flex: 1 }} value={meta.title} onChange={(e) => setMeta({ ...meta, title: e.currentTarget.value })} />
              </Group>
              <Group gap="xs" align="flex-end" mt={4}>
                <TextInput
                  size="xs"
                  label="Zbiór danych (event.dataset)"
                  description="np. cisco.asa, synology.dsm"
                  w={220}
                  value={meta.dataset}
                  onChange={(e) => setMeta({ ...meta, dataset: e.currentTarget.value })}
                />
                <NumberInput
                  size="xs"
                  label="Priorytet"
                  description="wyższy – wcześniej"
                  w={110}
                  min={1}
                  max={1000}
                  value={meta.priority}
                  onChange={(v) => setMeta({ ...meta, priority: Number(v) || 60 })}
                />
              </Group>
              <Text size="xs" fw={600} mt="xs">
                Rozpoznawanie – wszystkie zaznaczone warunki muszą być spełnione
              </Text>
              <Group gap="md" mt={2}>
                <Checkbox
                  size="xs"
                  label={`program „${cur.header.app || "—"}”`}
                  disabled={!cur.header.app}
                  checked={match.app}
                  onChange={(e) => setMatch({ ...match, app: e.currentTarget.checked })}
                />
                <Checkbox
                  size="xs"
                  label={`host „${cur.header.host || "—"}”`}
                  disabled={!cur.header.host}
                  checked={match.host}
                  onChange={(e) => setMatch({ ...match, host: e.currentTarget.checked })}
                />
                <Checkbox
                  size="xs"
                  label={`nadawca ${peer || "—"}`}
                  disabled={!peer.trim()}
                  checked={match.peer}
                  onChange={(e) => setMatch({ ...match, peer: e.currentTarget.checked })}
                />
              </Group>
              {mode === "regex" && (
                <>
                  <Checkbox
                    size="xs"
                    mt={4}
                    label="tylko wiadomości pasujące do oznaczonych wzorców (zalecane)"
                    description="bez tego dekoder przejmie każdą wiadomość spełniającą warunki powyżej, także taką, z której nie wyciągnie pól"
                    checked={byPatterns}
                    onChange={(e) => setByPatterns(e.currentTarget.checked)}
                  />
                  <Text size="xs" c="dimmed" mt={2}>
                    Stały fragment wiadomości do rozpoznawania oznacz etykietą „rozpoznawanie” (w każdym wzorcu).
                  </Text>
                </>
              )}
              {existing[meta.id] && (
                <Checkbox
                  size="xs"
                  mt={4}
                  color="red"
                  label={`zastąp istniejący dekoder „${existing[meta.id]}” (${meta.id})`}
                  checked={replace}
                  onChange={(e) => setReplace(e.currentTarget.checked)}
                />
              )}
              {hasTime && (
                <Group gap="xs" align="flex-end" mt="xs">
                  <Select
                    size="xs"
                    label={`Format czasu (przykład: ${timeSample || "—"})`}
                    w={300}
                    searchable
                    value={LAYOUTS.some((l) => l.value === timeLayout) ? timeLayout : null}
                    onChange={(v) => setTimeLayout(v ?? "")}
                    data={LAYOUTS.map((l) => ({ value: l.value, label: l.label }))}
                  />
                  <TextInput
                    size="xs"
                    label="albo układ Go"
                    w={190}
                    placeholder="2006-01-02 15:04:05"
                    value={timeLayout}
                    onChange={(e) => setTimeLayout(e.currentTarget.value)}
                  />
                  <TextInput size="xs" label="Strefa (opcjonalnie)" placeholder="Europe/Warsaw" w={140} value={timeZone} onChange={(e) => setTimeZone(e.currentTarget.value)} />
                </Group>
              )}
              {hasOutcome && (
                <Stack gap={4} mt="xs">
                  <Text size="xs" fw={600}>
                    Wynik – które wartości pola oznaczają…
                  </Text>
                  {outcomeValues.length > 0 && (
                    <Group gap={4}>
                      <Text size="xs" c="dimmed">
                        w próbkach:
                      </Text>
                      {outcomeValues.map((v) => (
                        <Group key={v} gap={2} wrap="nowrap">
                          <Code>{v}</Code>
                          {!outSuccess.includes(v) && !outFailure.includes(v) && (
                            <>
                              <Button size="compact-xs" variant="subtle" color="green" onClick={() => setOutSuccess((l) => [...l, v])}>
                                udane
                              </Button>
                              <Button size="compact-xs" variant="subtle" color="red" onClick={() => setOutFailure((l) => [...l, v])}>
                                nieudane
                              </Button>
                            </>
                          )}
                        </Group>
                      ))}
                    </Group>
                  )}
                  <Group gap="xs" grow>
                    <TagsInput size="xs" label="udane" value={outSuccess} onChange={setOutSuccess} />
                    <TagsInput size="xs" label="nieudane" value={outFailure} onChange={setOutFailure} />
                  </Group>
                </Stack>
              )}
            </Card>

            <Card withBorder p="sm">
              <Group justify="space-between" mb={4}>
                <Text fw={600} size="sm">
                  4. Sprawdzenie na wszystkich próbkach
                </Text>
                {sum && (
                  <Group gap={4}>
                    <Badge color={sum.candidate === sum.total ? "green" : sum.candidate > 0 ? "yellow" : "red"}>
                      ten dekoder: {sum.candidate} z {sum.total}
                    </Badge>
                    {sum.no_pattern > 0 && <Badge color="orange">bez wzorca: {sum.no_pattern}</Badge>}
                    {sum.other > 0 && <Badge color="blue">inne dekodery: {sum.other}</Badge>}
                    {sum.errors > 0 && <Badge color="red">błędy: {sum.errors}</Badge>}
                  </Group>
                )}
              </Group>
              {built.error && <MAlert color="gray">{built.error}</MAlert>}
              {test && !test.ok && <MAlert color="red">{test.error}</MAlert>}
              {test?.ok && test.results && (
                <ScrollArea.Autosize mah={300}>
                  <Table fz="xs" verticalSpacing={2}>
                    <Table.Tbody>
                      {test.results.map((r, i) => (
                        <Table.Tr
                          key={i}
                          style={{ cursor: "pointer" }}
                          bg={i === sel ? "var(--mantine-color-default-hover)" : undefined}
                          onClick={() => {
                            setSel(i);
                            setPending(null);
                          }}
                        >
                          <Table.Td w={18}>
                            <Text size="xs" c={matchedBy(i) ? "green" : r.decoder && r.decoder !== meta.id ? "blue" : "red"}>
                              {matchedBy(i) ? "✓" : r.decoder && r.decoder !== meta.id ? "↷" : "✗"}
                            </Text>
                          </Table.Td>
                          <Table.Td>
                            <Text size="xs" lineClamp={1} ff="monospace">
                              {r.header.message}
                            </Text>
                            {mode === "regex" && matchedBy(i) && (() => {
                              const ps = patternOf(r.header.message);
                              if (ps.length === 0) return null;
                              return (
                                <Text size="xs" c={ps.length > 1 ? "orange" : "dimmed"}>
                                  wzorzec z wiadomości {patternNo(ps[0])}
                                  {ps.length > 1
                                    ? ` – pasuje też do wzorca z wiadomości ${ps.slice(1).map(patternNo).join(", ")}; działa pierwszy, sprawdź akcję i wynik`
                                    : ""}
                                </Text>
                              );
                            })()}
                            {matchedBy(i) && (
                              <Text size="xs" c="dimmed">
                                {["timestamp", "user.name", "source.ip", "event.action", "event.outcome", "host.name"]
                                  .filter((k) => r.event[k])
                                  .map((k) => `${k}=${r.event[k]}`)
                                  .join("  ")}
                              </Text>
                            )}
                            {r.error && (
                              <Text size="xs" c="red">
                                {r.error}
                              </Text>
                            )}
                          </Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </ScrollArea.Autosize>
              )}
              <Text size="xs" c="dimmed" mt={4}>
                ✓ – rozpoznana tym dekoderem z polami, ✗ – nie (kliknij, aby oznaczyć ją jako kolejny wzorzec), ↷ – obsługuje ją inny dekoder.
              </Text>
            </Card>

            <Card withBorder p="sm">
              <Title order={6} mb={4}>
                Definicja
              </Title>
              <ScrollArea.Autosize mah={220}>
                <Code block fz="xs">
                  {built.yaml || "—"}
                </Code>
              </ScrollArea.Autosize>
              <Group mt="xs" gap="xs" align="flex-end">
                <Button size="xs" variant="default" leftSection={<IconEdit size={14} />} disabled={!built.yaml} onClick={() => onEdit(finalYAML())}>
                  Otwórz w edytorze
                </Button>
                {admin && (
                  <>
                    <TextInput size="xs" placeholder="opis zmiany" style={{ flex: 1 }} value={note} onChange={(e) => setNote(e.currentTarget.value)} />
                    <Button size="xs" color="green" leftSection={<IconWand size={14} />} disabled={!built.yaml} loading={saving} onClick={() => void save()}>
                      Zapisz i wdroż
                    </Button>
                  </>
                )}
              </Group>
            </Card>
          </Stack>
        </SimpleGrid>
      )}
      {!cur && samples.length > 0 && !loading && (
        <Text size="sm" c="dimmed">
          Kliknij „Wczytaj”, aby rozebrać próbki.
        </Text>
      )}
    </Stack>
  );
}
