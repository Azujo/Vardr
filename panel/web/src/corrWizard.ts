// Logika kreatora korelacji (bez interfejsu): kroki z przykładowych
// zdarzeń (istniejąca reguła albo nowa reguła bazowa z wybranych pól),
// klucz wspólny dla kroków (także pod różnymi nazwami pól – aliasy),
// podpowiedź typu i okna oraz złożenie YAML w formacie Sigma Correlation
// (internal/detect/correlation.go).

export interface WizRule {
  id: string;
  name?: string;
  title: string;
  level: string;
  file: string;
  threshold: boolean;
}

export interface WizEvent {
  event_id: string;
  timestamp: string;
  dataset: string;
  host: string;
  user: string;
  code: number;
  message: string;
  fields: Record<string, string>;
  product: string;
  service: string;
  rules: WizRule[];
}

// Wybór reguły bazowej dla zdarzenia: istniejąca (id) albo nowa z pól.
export type Choice = { kind: "rule"; id: string } | { kind: "new"; fields: string[] };

export interface Step {
  key: string; // podpis wyboru (zdarzenia o tym samym podpisie to jeden krok)
  choice: Choice;
  events: WizEvent[]; // przykłady kroku (rosnąco po czasie)
  first: number; // czas pierwszego przykładu (ms)
  rule?: WizRule; // istniejąca reguła
  title: string;
}

export type CorrType = "event_count" | "value_count" | "temporal" | "temporal_ordered";

export const typeLabels: Record<CorrType, string> = {
  event_count: "liczba zdarzeń (event_count)",
  value_count: "liczba różnych wartości pola (value_count)",
  temporal: "wszystkie kroki w oknie, dowolna kolejność (temporal)",
  temporal_ordered: "wszystkie kroki w oknie, w kolejności (temporal_ordered)",
};

// Pole klucza: nazwa w group-by i pole w każdym kroku (gdy różne – alias).
export interface KeyCandidate {
  name: string;
  fields: string[]; // pole w kolejnych krokach
  value: string; // przykładowa wspólna wartość
  score: number;
}

// Pola, które nie nadają się na klucz ani na pole value_count (stałe
// rodzaju zdarzenia, opisy techniczne).
const notKey = new Set([
  "EventID",
  "Channel",
  "event.dataset",
  "event.provider",
  "event.action",
  "event.outcome",
  "Keywords",
  "Level",
  "Task",
  "Opcode",
  "Version",
  "EventRecordID",
  "ProcessID",
  "ThreadID",
  "message",
  "process.command_line",
  "LogonType",
  "Status",
  "SubStatus",
  "FailureReason",
  "KeyLength",
  "LmPackageName",
  "AuthenticationPackageName",
  "LogonProcessName",
  "PrivilegeList",
  "SidHistory",
]);

function trivial(v: string): boolean {
  const t = v.trim();
  if (t.length < 2 || t === "-" || t.startsWith("%%") || /^0x0+$/i.test(t) || t === "S-1-0-0") return true;
  if (/^\d{1,3}$/.test(t)) return true; // krótkie liczby (typy, kody)
  return false;
}

export function keyable(field: string, value: string): boolean {
  return !notKey.has(field) && !trivial(value);
}

// Waga pola klucza: tożsamość, konto, adres, komputer.
function fieldScore(f: string): number {
  const l = f.toLowerCase();
  if (l === "user.identity") return 6;
  if (l.endsWith("sid")) return 5;
  if (l.includes("username") || l === "user.name" || l.includes("membername")) return 4;
  if (l === "source.ip" || l.includes("ipaddress") || l.endsWith(".ip")) return 3;
  if (l === "host.name" || l.includes("workstation")) return 2;
  return 1;
}

// ---- kroki ----

// Domyślny wybór: pierwsza pasująca reguła bez progu, a gdy takiej nie ma –
// nowa reguła z pól rodzaju zdarzenia.
export function defaultChoice(e: WizEvent): Choice {
  const r = e.rules.find((x) => !x.threshold);
  if (r) return { kind: "rule", id: r.id };
  return { kind: "new", fields: defaultFields(e) };
}

export function defaultFields(e: WizEvent): string[] {
  const out: string[] = [];
  if (e.fields["EventID"]) out.push("EventID");
  if (e.product !== "windows") {
    if (e.fields["event.action"]) out.push("event.action");
    if (e.fields["event.outcome"]) out.push("event.outcome");
  }
  if (out.length === 0 && e.fields["event.action"]) out.push("event.action");
  return out;
}

// Pola nowej reguły bazowej z wartościami (logsource zawiera już produkt;
// bez produktu reguła wybiera zdarzenia polem event.dataset).
export function selectionOf(e: WizEvent, fields: string[]): [string, string][] {
  const sel: [string, string][] = [];
  if (!e.product) sel.push(["event.dataset", e.dataset]);
  for (const f of fields) {
    if (f === "event.dataset" && !e.product) continue;
    const v = e.fields[f];
    if (v !== undefined) sel.push([f, v]);
  }
  return sel;
}

function choiceKey(e: WizEvent, c: Choice): string {
  if (c.kind === "rule") return "rule:" + c.id;
  const sel = selectionOf(e, c.fields)
    .map(([k, v]) => `${k}=${v.toLowerCase()}`)
    .sort();
  return `new:${e.product}/${e.service}/` + sel.join("\x1f");
}

export function eventLabel(e: WizEvent): string {
  const what = e.code ? `${e.code}` : e.fields["event.action"] || e.dataset;
  return `${what} · ${e.dataset}`;
}

// Kroki: zdarzenia o tym samym wyborze to jeden krok; kolejność według
// pierwszego przykładu.
export function buildSteps(events: WizEvent[], choices: Record<string, Choice>): Step[] {
  const byKey = new Map<string, Step>();
  const sorted = [...events].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
  for (const e of sorted) {
    const c = choices[e.event_id] ?? defaultChoice(e);
    const k = choiceKey(e, c);
    let st = byKey.get(k);
    if (!st) {
      const rule = c.kind === "rule" ? e.rules.find((r) => r.id === c.id) : undefined;
      st = { key: k, choice: c, events: [], first: Date.parse(e.timestamp), rule, title: rule?.title ?? eventTitle(e) };
      byKey.set(k, st);
    }
    st.events.push(e);
  }
  return [...byKey.values()].sort((a, b) => a.first - b.first);
}

// Tytuł nowej reguły bazowej (z rodzaju zdarzenia).
const knownTitles: Record<string, string> = {
  "4624": "Udane logowanie",
  "4625": "Nieudane logowanie",
  "4634": "Wylogowanie",
  "4648": "Logowanie z jawnie podanym kontem",
  "4672": "Logowanie z uprawnieniami specjalnymi",
  "4688": "Utworzenie procesu",
  "4720": "Utworzono konto",
  "4722": "Włączono konto",
  "4724": "Reset hasła konta",
  "4725": "Wyłączono konto",
  "4726": "Usunięto konto",
  "4728": "Dodano do grupy globalnej",
  "4732": "Dodano do grupy lokalnej",
  "4740": "Zablokowano konto",
  "4756": "Dodano do grupy uniwersalnej",
  "4768": "Bilet Kerberos TGT",
  "4769": "Bilet usługi Kerberos",
  "4771": "Błąd uwierzytelnienia Kerberos",
  "4776": "Weryfikacja poświadczeń NTLM",
  "1102": "Wyczyszczono dziennik zabezpieczeń",
  "7045": "Zainstalowano usługę",
};

export function eventTitle(e: WizEvent): string {
  if (e.product === "windows" && knownTitles[String(e.code)]) return `${knownTitles[String(e.code)]} (${e.code})`;
  const parts = [e.fields["event.action"], e.fields["event.outcome"]].filter(Boolean);
  return parts.length ? `${e.dataset}: ${parts.join(" ")}` : e.code ? `${e.dataset}: zdarzenie ${e.code}` : e.dataset;
}

// ---- klucz ----

// Kandydaci na klucz: wartość obecna w każdym kroku (w dowolnym polu).
// Jeden krok: wartość wspólna wszystkim przykładom.
export function keyCandidates(steps: Step[]): KeyCandidate[] {
  if (steps.length === 0) return [];
  const groups: WizEvent[][] = steps.length === 1 ? steps[0].events.map((e) => [e]) : steps.map((s) => s.events);
  if (groups.length < 2) return [];
  // wartość → pola w każdej grupie
  const per = groups.map((evs) => {
    const m = new Map<string, Set<string>>();
    for (const e of evs) {
      for (const [f, v] of Object.entries(e.fields)) {
        if (!keyable(f, v)) continue;
        const k = v.trim().toLowerCase();
        if (!m.has(k)) m.set(k, new Set());
        m.get(k)!.add(f);
      }
    }
    return m;
  });
  const out: KeyCandidate[] = [];
  const seen = new Set<string>();
  for (const [val, fields0] of per[0]) {
    if (!per.every((m) => m.has(val))) continue;
    // Pole w każdej grupie: najpierw to samo we wszystkich, potem najlepsze.
    const common = [...fields0].filter((f) => per.every((m) => m.get(val)!.has(f)));
    let fields: string[];
    if (common.length) {
      const best = common.sort((a, b) => fieldScore(b) - fieldScore(a) || a.localeCompare(b))[0];
      fields = per.map(() => best);
    } else {
      fields = per.map((m) => [...m.get(val)!].sort((a, b) => fieldScore(b) - fieldScore(a) || a.localeCompare(b))[0]);
    }
    if (steps.length === 1) fields = [fields[0]];
    const sig = fields.join("|");
    if (seen.has(sig)) continue;
    seen.add(sig);
    const same = fields.every((f) => f === fields[0]);
    out.push({
      name: same ? fields[0] : aliasName(fields),
      fields,
      value: val,
      score: Math.min(...fields.map(fieldScore)) * 10 + (same ? 1 : 0),
    });
  }
  return out.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name)).slice(0, 12);
}

function aliasName(fields: string[]): string {
  const l = fields.join(" ").toLowerCase();
  if (l.includes("sid")) return "account_sid";
  if (l.includes("user") || l.includes("member")) return "account";
  if (l.includes("ip")) return "address";
  if (l.includes("host") || l.includes("workstation")) return "computer";
  return "key";
}

// Pola, których wartości różnią się między przykładami (value_count).
export function valueFields(step: Step | undefined): { field: string; values: number }[] {
  if (!step) return [];
  const m = new Map<string, Set<string>>();
  for (const e of step.events) {
    for (const [f, v] of Object.entries(e.fields)) {
      if (!keyable(f, v)) continue;
      if (!m.has(f)) m.set(f, new Set());
      m.get(f)!.add(v.toLowerCase());
    }
  }
  return [...m.entries()]
    .filter(([, vs]) => vs.size > 1)
    .map(([field, vs]) => ({ field, values: vs.size }))
    .sort((a, b) => b.values - a.values || fieldScore(b.field) - fieldScore(a.field) || a.field.localeCompare(b.field));
}

// ---- typ i okno ----

export const windows = ["5m", "10m", "15m", "30m", "1h", "2h", "4h", "8h", "12h", "24h"];

export function windowMs(w: string): number {
  const n = parseInt(w, 10);
  return w.endsWith("h") ? n * 3600_000 : n * 60_000;
}

// Okno: dwukrotność odstępu między przykładami, co najmniej 5 min.
export function suggestWindow(events: WizEvent[]): string {
  if (events.length < 2) return "15m";
  const ts = events.map((e) => Date.parse(e.timestamp));
  const span = Math.max(...ts) - Math.min(...ts);
  return windows.find((w) => windowMs(w) >= span * 2) ?? "24h";
}

export function spanMs(events: WizEvent[]): number {
  if (events.length < 2) return 0;
  const ts = events.map((e) => Date.parse(e.timestamp));
  return Math.max(...ts) - Math.min(...ts);
}

export function suggestType(steps: Step[]): CorrType {
  if (steps.length >= 2) return "temporal_ordered";
  return "event_count";
}

// ---- YAML ----

export interface WizardState {
  title: string;
  id: string;
  level: string;
  description: string;
  instructions: string;
  type: CorrType;
  count: number;
  field: string;
  window: string;
  key: KeyCandidate | null;
  generate: boolean;
  baseIds: Record<string, { id: string; name: string }>; // krok (key) → id i nazwa nowej reguły bazowej
}

// Wartość YAML w apostrofach (bez interpretacji znaków specjalnych).
export function q(s: string): string {
  return "'" + s.replace(/'/g, "''") + "'";
}

// Wartość Sigmy dosłownie: * ? i \ jako znaki, nie maski.
export function sigmaLiteral(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/\*/g, "\\*").replace(/\?/g, "\\?");
}

function block(text: string, indent: string): string {
  return text
    .trim()
    .split("\n")
    .map((l) => indent + l)
    .join("\n");
}

export function slug(s: string): string {
  return (
    s
      .toLowerCase()
      .normalize("NFD")
      .replace(/[̀-ͯ]/g, "")
      .replace(/ł/g, "l")
      .replace(/[^a-z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .slice(0, 40) || "regula"
  );
}

// UUID v4 (crypto.randomUUID działa tylko na https; getRandomValues wszędzie).
export function uuid(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export function validate(st: WizardState, steps: Step[]): string | undefined {
  if (steps.length === 0) return "dodaj przykładowe zdarzenia";
  if (!st.title.trim()) return "podaj tytuł";
  for (const s of steps) {
    if (s.choice.kind === "new" && selectionOf(s.events[0], s.choice.fields).length === 0)
      return `krok „${s.title}”: wybierz co najmniej jedno pole nowej reguły bazowej`;
    if (s.rule?.threshold) return `krok „${s.title}”: reguła progowa nie może być bazą korelacji – wybierz inną albo nową`;
  }
  const temporal = st.type === "temporal" || st.type === "temporal_ordered";
  if (temporal && steps.length < 2) return "korelacja czasowa wymaga co najmniej dwóch różnych kroków";
  if (st.type === "value_count" && !st.field) return "wybierz pole, którego różne wartości liczyć";
  if (!temporal && (st.count < 2 || st.count > 10000)) return "liczba: od 2 do 10 000";
  if (st.key && st.key.fields.length !== steps.length && !(steps.length === 1 && st.key.fields.length === 1))
    return "klucz nie pasuje do kroków – wybierz go ponownie";
  return undefined;
}

// buildYAML składa reguły bazowe (nowe kroki) i regułę korelacyjną.
export function buildYAML(st: WizardState, steps: Step[]): string {
  const docs: string[] = [];
  const refs: { ref: string; comment: string }[] = [];
  steps.forEach((s, i) => {
    if (s.choice.kind === "rule") {
      refs.push({ ref: s.choice.id, comment: s.title });
      return;
    }
    const base = st.baseIds[s.key] ?? { id: uuid(), name: `${slug(st.title)}_krok${i + 1}` };
    const e = s.events[0];
    const lines = [
      `title: ${q(`${s.title} – krok ${i + 1} korelacji „${st.title.trim()}”`)}`,
      `id: ${base.id}`,
      `name: ${base.name}`,
      "status: experimental",
      `description: ${q(`Reguła bazowa korelacji „${st.title}” z kreatora w panelu.`)}`,
      "level: low",
    ];
    if (e.product) {
      lines.push("logsource:", `  product: ${e.product}`);
      if (e.service) lines.push(`  service: ${e.service}`);
    }
    lines.push("detection:", "  selection:");
    for (const [f, v] of selectionOf(e, s.choice.fields)) {
      lines.push(f === "EventID" && /^\d+$/.test(v) ? `    ${f}: ${v}` : `    ${q(f)}: ${q(sigmaLiteral(v))}`);
    }
    lines.push("  condition: selection");
    docs.push(lines.join("\n"));
    refs.push({ ref: base.name, comment: s.title });
  });

  const temporal = st.type === "temporal" || st.type === "temporal_ordered";
  const c = [`title: ${q(st.title.trim())}`, `id: ${st.id}`, "status: experimental"];
  if (st.description.trim()) c.push("description: |", block(st.description, "  "));
  c.push(`level: ${st.level}`, "correlation:", `  type: ${st.type}`, "  rules:");
  for (const r of refs) c.push(`    - ${r.ref} # ${r.comment.replace(/\n/g, " ")}`);
  if (st.key) {
    c.push("  group-by:", `    - ${q(st.key.name)}`);
  }
  c.push(`  timespan: ${st.window}`);
  if (st.key && steps.length > 1 && !st.key.fields.every((f) => f === st.key!.name)) {
    c.push("  aliases:", `    ${q(st.key.name)}:`);
    refs.forEach((r, i) => c.push(`      ${r.ref}: ${q(st.key!.fields[i])}`));
  }
  if (!temporal) {
    c.push("  condition:", `    gte: ${st.count}`);
    if (st.type === "value_count") c.push(`    field: ${q(st.field)}`);
  }
  c.push(`  generate: ${st.generate ? "true" : "false"}`);
  if (st.instructions.trim()) c.push("heimdall:", "  instructions: |", block(st.instructions, "    "));
  docs.push(c.join("\n"));
  return docs.join("\n---\n") + "\n";
}
