// SPDX-License-Identifier: AGPL-3.0-or-later

// Logika kreatora dekoderów (bez interfejsu): rozpoznanie rodzaju treści,
// rozbiór par klucz=wartość i JSON, budowa wyrażenia regularnego z
// zaznaczonych fragmentów, rozpoznanie formatu czasu i złożenie definicji
// YAML w formacie internal/decode (parser regex, kv albo json). Teksty –
// decoders: wizard.* (etykiety, formaty czasu, błędy).
import i18n from "./i18n";

export type LabelKey =
  | "time"
  | "user"
  | "domain"
  | "src_ip"
  | "dst_ip"
  | "dst_port"
  | "host"
  | "action"
  | "outcome"
  | "code"
  | "process"
  | "message"
  | "custom"
  | "any"
  | "match";

export interface LabelDef {
  key: LabelKey;
  label: string;
  color: string;
  target?: string; // pole zdarzenia (fields w dekoderze)
  group?: string; // nazwa grupy w wyrażeniu
  hint?: string;
}

export const LABELS: LabelDef[] = [
  { key: "time", label: "czas", color: "violet", group: "time", hint: "czas zdarzenia (lepszy niż z nagłówka)" },
  { key: "user", label: "użytkownik", color: "blue", target: "user.name", group: "user" },
  { key: "domain", label: "domena", color: "indigo", target: "user.domain", group: "domain" },
  { key: "src_ip", label: "adres źródłowy", color: "orange", target: "source.ip", group: "src_ip" },
  { key: "dst_ip", label: "adres docelowy", color: "yellow", target: "destination.ip", group: "dst_ip" },
  { key: "dst_port", label: "port docelowy", color: "lime", target: "destination.port", group: "dst_port" },
  { key: "host", label: "komputer / urządzenie", color: "cyan", target: "host.name", group: "host" },
  { key: "action", label: "akcja", color: "teal", target: "event.action", group: "action" },
  { key: "outcome", label: "wynik", color: "red", group: "result", hint: "udane / nieudane – wartości ustawisz niżej" },
  { key: "code", label: "kod zdarzenia", color: "grape", target: "event.code", group: "code", hint: "liczba" },
  { key: "process", label: "program / proces", color: "pink", target: "process.name", group: "process" },
  { key: "message", label: "treść", color: "gray", target: "message", group: "msg" },
  { key: "custom", label: "własne pole…", color: "green", hint: "nazwa pola, np. vpn.tunnel" },
  { key: "any", label: "dowolne", color: "gray", hint: "fragment zmienny między wiadomościami, bez zapisu (np. protokół, numer sesji)" },
  { key: "match", label: "rozpoznawanie", color: "dark", hint: "stały fragment, po którym dekoder rozpozna te wiadomości" },
];

// Nazwy i opisy etykiet w bieżącym języku (decoders: label.<klucz>, labelHint.<klucz>).
for (const l of LABELS) {
  Object.defineProperty(l, "label", { enumerable: true, get: () => i18n.t(`decoders:label.${l.key}`) });
  if (l.hint !== undefined) Object.defineProperty(l, "hint", { enumerable: true, get: () => i18n.t(`decoders:labelHint.${l.key}`) });
}

export const labelDef = (k: LabelKey) => LABELS.find((l) => l.key === k)!;

export interface Span {
  start: number;
  end: number;
  key: LabelKey;
  custom?: string; // nazwa pola dla „własne pole”
}

// ---- rodzaj treści ----

export type Mode = "regex" | "kv" | "json";

const kvRe = /(?:^|[\s,])([A-Za-z_][\w.-]*)=("(?:[^"\\]|\\.)*"|[^\s,]*)/g;

export function detectMode(msg: string): Mode {
  const t = msg.trim();
  if (t.startsWith("{")) {
    try {
      JSON.parse(t);
      return "json";
    } catch {
      /* nie JSON */
    }
  }
  return [...t.matchAll(kvRe)].length >= 3 ? "kv" : "regex";
}

// parseKV jak internal/decode (wartości w cudzysłowach mogą mieć spacje).
export function parseKV(msg: string): [string, string][] {
  const out: [string, string][] = [];
  for (const m of msg.matchAll(kvRe)) {
    let v = m[2];
    if (v.startsWith('"')) v = v.slice(1, -1).replace(/\\(.)/g, "$1");
    out.push([m[1], v]);
  }
  return out;
}

// flattenJSON jak internal/decode: a.b.c, tablice z indeksem.
export function flattenJSON(msg: string): [string, string][] {
  const out: [string, string][] = [];
  const walk = (v: unknown, p: string) => {
    if (v === null || v === undefined) return;
    if (Array.isArray(v)) v.forEach((x, i) => walk(x, p ? `${p}.${i}` : String(i)));
    else if (typeof v === "object") for (const [k, x] of Object.entries(v as object)) walk(x, p ? `${p}.${k}` : k);
    else out.push([p, String(v)]);
  };
  try {
    walk(JSON.parse(msg), "");
  } catch {
    /* pusto */
  }
  return out;
}

// ---- czas ----

export interface Layout {
  value: string; // układ Go albo rfc3339 / unix / unix_ms
  label: string;
  re: string; // wyrażenie dopasowujące wartość
  test: RegExp;
  noYear?: boolean;
}

export const LAYOUTS: Layout[] = [
  {
    value: "rfc3339",
    label: "2006-01-02T15:04:05Z (ISO 8601)",
    re: String.raw`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})`,
    test: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/,
  },
  {
    value: "2006-01-02 15:04:05.000",
    label: "2006-01-02 15:04:05.000",
    re: String.raw`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}`,
    test: /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$/,
  },
  {
    value: "2006-01-02 15:04:05 -0700",
    label: "2006-01-02 15:04:05 +0200",
    re: String.raw`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}`,
    test: /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}$/,
  },
  { value: "2006-01-02T15:04:05", label: "2006-01-02T15:04:05", re: String.raw`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`, test: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/ },
  { value: "2006-01-02 15:04:05", label: "2006-01-02 15:04:05", re: String.raw`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`, test: /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/ },
  { value: "2006/01/02 15:04:05", label: "2006/01/02 15:04:05", re: String.raw`\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}`, test: /^\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}$/ },
  { value: "02.01.2006 15:04:05", label: "02.01.2006 15:04:05", re: String.raw`\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}`, test: /^\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}$/ },
  { value: "02/01/2006 15:04:05", label: "02/01/2006 15:04:05", re: String.raw`\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}`, test: /^\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}:\d{2}$/ },
  { value: "01/02/2006 15:04:05", label: "01/02/2006 15:04:05", re: String.raw`\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}`, test: /^$/ },
  { value: "Jan _2 2006 15:04:05", label: "Oct  9 2026 13:24:55", re: String.raw`[A-Z][a-z]{2} +\d{1,2} \d{4} \d{2}:\d{2}:\d{2}`, test: /^[A-Z][a-z]{2} +\d{1,2} \d{4} \d{2}:\d{2}:\d{2}$/ },
  {
    value: "Jan/02/2006 15:04:05",
    label: "Oct/09/2026 13:24:55 (MikroTik)",
    re: String.raw`[A-Z][a-z]{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}`,
    test: /^[A-Z][a-z]{2}\/\d{2}\/\d{4} \d{2}:\d{2}:\d{2}$/,
  },
  {
    value: "Jan _2 15:04:05",
    label: "Oct  9 13:24:55",
    re: String.raw`[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}`,
    test: /^[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}$/,
    noYear: true,
  },
  { value: "unix", label: "sekundy od 1970", re: String.raw`\d{10}`, test: /^\d{10}$/ },
  { value: "unix_ms", label: "milisekundy od 1970", re: String.raw`\d{13}`, test: /^\d{13}$/ },
];

// Dopiski do nazw formatów w bieżącym języku (decoders: layout.<klucz>).
const layoutNotes: Record<string, string> = {
  "2006-01-02T15:04:05": "noZone",
  "02/01/2006 15:04:05": "dayMonth",
  "01/02/2006 15:04:05": "monthDay",
  "Jan _2 15:04:05": "noYear",
  unix: "unix",
  unix_ms: "unixMs",
};
for (const l of LAYOUTS) {
  const key = layoutNotes[l.value];
  if (!key) continue;
  const base = l.label;
  Object.defineProperty(l, "label", {
    enumerable: true,
    get: () => (key.startsWith("unix") ? i18n.t(`decoders:layout.${key}`) : `${base} (${i18n.t(`decoders:layout.${key}`)})`),
  });
}

export function guessLayout(v: string): Layout | undefined {
  return LAYOUTS.find((l) => l.test.test(v.trim()));
}

// ---- wyrażenie regularne z zaznaczeń ----

const reEscape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Uogólnienie stałego tekstu między polami: odstępy → \s+, liczby → \d+
// (identyfikatory sesji, PID), reszta dosłownie.
function generalize(s: string): string {
  let out = "";
  for (const m of s.matchAll(/(\s+)|(\d+)|([^\s\d]+)/g)) {
    if (m[1]) out += String.raw`\s+`;
    else if (m[2]) out += String.raw`\d+`;
    else out += reEscape(m[3]);
  }
  return out;
}

// context: końcówka tekstu przed polem (do 2 słów) – kotwica wzorca.
function context(gap: string): string {
  const m = /(\S+\s*){0,2}$/.exec(gap);
  return m ? m[0] : "";
}

export function groupName(sp: Span): string {
  if (sp.key === "custom") return "f_" + (sp.custom ?? "pole").replace(/[^A-Za-z0-9]/g, "_").toLowerCase();
  return labelDef(sp.key).group ?? "pole";
}

// shape: wzorzec o kształcie wartości (cyfry, litery, znaki) – części czasu
// zaznaczone osobno (data, godzina, strefa) albo czas w nieznanym formacie.
function shape(v: string): string {
  let out = "";
  for (const m of v.matchAll(/(\s+)|(\d+)|([A-Za-z]+)|(.)/g)) {
    if (m[1]) out += String.raw`\s+`;
    else if (m[2]) out += String.raw`\d+`;
    else if (m[3]) out += "[A-Za-z]+";
    else out += reEscape(m[4]);
  }
  return out;
}

function valuePattern(sp: Span, value: string, next: string, layout: Layout | undefined, timeParts: number): string {
  if (sp.key === "time") return layout && timeParts === 1 ? layout.re : shape(value);
  if (sp.key === "src_ip" || sp.key === "dst_ip") return "[0-9A-Fa-f.:]+";
  if (/^\d+$/.test(value)) return String.raw`\d+`;
  const spaces = /\s/.test(value);
  if (next === "") return spaces ? ".+" : String.raw`\S+`;
  return spaces ? ".+?" : String.raw`\S+?`;
}

export interface BuiltPattern {
  regex: string; // składnia RE2 (Go): (?P<nazwa>…)
  groups: string[];
  error?: string;
}

// buildRegex: wzorzec dla jednej wiadomości. Pola – grupy nazwane; tekst
// między nimi uogólniony; długie odcinki zastąpione „.*?” z kotwicą
// z ostatnich słów przed polem.
export function buildRegex(msg: string, spans: Span[], layouts: Record<string, Layout | undefined>): BuiltPattern {
  const fields = spans.filter((s) => s.key !== "match").sort((a, b) => a.start - b.start);
  if (fields.length === 0) return { regex: "", groups: [], error: i18n.t("decoders:wizard.err.noField") };
  let re = "^";
  let pos = 0;
  const groups: string[] = [];
  const used = new Map<string, number>();
  const timeParts = fields.filter((s) => s.key === "time").length;
  fields.forEach((sp, i) => {
    const gap = msg.slice(pos, sp.start);
    if (i === 0) {
      re += gap.length === 0 ? "" : ".*?" + generalize(context(gap));
    } else if (gap.length <= 40) {
      re += generalize(gap);
    } else {
      re += ".*?" + generalize(context(gap));
    }
    const value = msg.slice(sp.start, sp.end);
    const nextGap = i + 1 < fields.length ? msg.slice(sp.end, fields[i + 1].start) : "";
    if (sp.key === "any") {
      // Zmienny fragment bez zapisu: tyle słów, ile w przykładzie.
      re += `(?:${value.split(/\s+/).map(() => String.raw`\S+`).join(String.raw`\s+`)})`;
      groups.push("");
      pos = sp.end;
      return;
    }
    let name = groupName(sp);
    const n = used.get(name) ?? 0;
    used.set(name, n + 1);
    if (n > 0) name = `${name}${n + 1}`;
    groups.push(name);
    re += `(?P<${name}>${valuePattern(sp, value, nextGap, layouts[name], timeParts)})`;
    pos = sp.end;
  });
  // Pole na końcu bez spacji – wartość kończy się na odstępie albo końcu treści.
  const tail = msg.slice(pos);
  if (tail.length > 0 && !/\s/.test(tail[0])) re += reEscape(tail[0]);
  return { regex: re, groups };
}

// checkRegex: sprawdzenie wzorca w przeglądarce (JS ma inną składnię grup).
export function checkRegex(regex: string, msg: string): Record<string, string> | null {
  try {
    const m = new RegExp(regex.replace(/\(\?P</g, "(?<")).exec(msg);
    return m ? { ...(m.groups ?? {}) } : null;
  } catch {
    return null;
  }
}

// ---- definicja YAML ----

const q = (s: string) => `'${s.replace(/'/g, "''")}'`;

export interface PatternDef {
  sampleIndex: number;
  msg: string;
  spans: Span[];
  action?: string; // stała akcja dla tego wzorca
  outcome?: "" | "success" | "failure"; // stały wynik dla tego wzorca
}

export interface WizardState {
  id: string;
  title: string;
  dataset: string;
  priority: number;
  mode: Mode;
  // rozpoznawanie
  matchApp?: string;
  matchHost?: string;
  matchPeer?: string;
  matchContains: string[]; // kv/json: wymagane pola
  // regex: rozpoznawanie po wzorcach – wiadomość musi pasować do któregoś
  // oznaczonego wzorca (inaczej dekoder przejmuje każdą wiadomość, która
  // spełnia warunki programu/hosta/nadawcy, także bez pól)
  matchByPatterns: boolean;
  // regex
  patterns: PatternDef[];
  // kv / json: klucz → etykieta
  keyLabels: Record<string, { key: LabelKey; custom?: string }>;
  // czas
  timeLayout: string;
  timeZone: string;
  // wynik z pola
  outcomeSuccess: string[];
  outcomeFailure: string[];
  samples: string[];
}

export function targetOf(key: LabelKey, custom?: string): string | undefined {
  if (key === "custom") return custom?.trim() || undefined;
  return labelDef(key).target;
}

export function buildYAML(st: WizardState): { yaml: string; error?: string } {
  const L: string[] = [];
  L.push(`id: ${st.id}`);
  L.push(`title: ${q(st.title)}`);
  L.push("description: |");
  L.push(`  ${i18n.t("decoders:wizard.yamlDescription")}`);
  L.push("version: 1");
  L.push(`priority: ${st.priority}`);
  L.push(`dataset: ${st.dataset}`);
  // wzorce (tryb tekstowy) – potrzebne też do rozpoznawania
  const built = st.mode === "regex" ? patternRegexes(st) : [];
  const bad = built.find((b) => b.error);
  if (bad) return { yaml: "", error: bad.error };
  if (st.mode === "regex" && built.length === 0) return { yaml: "", error: i18n.t("decoders:wizard.err.noPattern") };

  // match: program/host/nadawca – wszystkie naraz; fragmenty „rozpoznawanie”
  // i wzorce – osobno dla każdego rodzaju wiadomości (any: którykolwiek),
  // bo wszystkie fragmenty contains muszą wystąpić jednocześnie.
  const m: string[] = [];
  if (st.matchApp) m.push(`  app: [${q(st.matchApp)}]`);
  if (st.matchHost) m.push(`  host: [${q(st.matchHost)}]`);
  if (st.matchPeer) m.push(`  peer: [${st.matchPeer.includes("/") ? st.matchPeer : st.matchPeer + (st.matchPeer.includes(":") ? "/128" : "/32")}]`);
  if (st.mode === "regex") {
    const alts = st.patterns.map((p, i) => {
      const frags = [...new Set(p.spans.filter((x) => x.key === "match").map((x) => p.msg.slice(x.start, x.end)))];
      const a: string[] = [];
      if (st.matchByPatterns) a.push(`regex: ${q(built[i].regex)}`);
      if (frags.length) a.push(`contains: [${frags.map(q).join(", ")}]`);
      return a;
    });
    const withFrags = alts.filter((a) => a.length > 0).length;
    if (withFrags > 0 && withFrags < alts.length)
      return {
        yaml: "",
        error: i18n.t("decoders:wizard.err.matchEach"),
      };
    if (withFrags === 1 && !st.matchByPatterns) m.push(`  contains: ${alts[0][0].slice("contains: ".length)}`);
    else if (withFrags > 0) {
      m.push("  any:");
      for (const a of alts) m.push(`    - {${a.join(", ")}}`);
    }
  } else if (st.matchContains.length) m.push(`  contains: [${st.matchContains.map(q).join(", ")}]`);
  if (m.length === 0) return { yaml: "", error: i18n.t("decoders:wizard.err.noMatch") };
  L.push("match:", ...m);

  const fields = new Map<string, string[]>(); // pole zdarzenia → źródła
  const timeSources: string[] = [];
  let outcomeSource = "";
  const addField = (target: string | undefined, src: string) => {
    if (!target) return;
    const l = fields.get(target) ?? [];
    if (!l.includes(src)) l.push(src);
    fields.set(target, l);
  };

  if (st.mode === "regex") {
    L.push("parser:", "  type: regex", "  patterns:");
    st.patterns.forEach((p, pi) => {
      const b = built[pi];
      L.push(`    - regex: ${q(b.regex)}`);
      const set: string[] = [];
      if (p.action?.trim()) set.push(`event.action: ${q(p.action.trim())}`);
      if (p.outcome) set.push(`event.outcome: ${p.outcome}`);
      if (set.length) L.push(`      set: {${set.join(", ")}}`);
      const fsorted = p.spans.filter((x) => x.key !== "match").sort((a, b2) => a.start - b2.start);
      fsorted.forEach((sp, i) => {
        const g = b.groups[i];
        if (sp.key === "time") {
          if (!timeSources.includes(g)) timeSources.push(g);
        } else if (sp.key === "outcome") outcomeSource = outcomeSource || g;
        else addField(targetOf(sp.key, sp.custom), g);
      });
    });
  } else {
    L.push("parser:", `  type: ${st.mode}`);
    for (const [k, v] of Object.entries(st.keyLabels)) {
      if (v.key === "time") timeSources.push(k);
      else if (v.key === "outcome") outcomeSource = outcomeSource || k;
      else if (v.key !== "match") addField(targetOf(v.key, v.custom), k);
    }
  }

  if (fields.size) {
    L.push("fields:");
    for (const [t, src] of fields) L.push(`  ${t}: ${src.length === 1 ? src[0] : `[${src.join(", ")}]`}`);
  }
  if (outcomeSource) {
    if (st.outcomeSuccess.length === 0 && st.outcomeFailure.length === 0)
      return { yaml: "", error: i18n.t("decoders:wizard.err.outcome") };
    L.push("outcome:", `  field: ${outcomeSource}`);
    if (st.outcomeFailure.length) L.push(`  failure: [${st.outcomeFailure.map(q).join(", ")}]`);
    if (st.outcomeSuccess.length) L.push(`  success: [${st.outcomeSuccess.map(q).join(", ")}]`);
  }
  if (timeSources.length) {
    const lay = LAYOUTS.find((l) => l.value === st.timeLayout);
    if (!st.timeLayout) return { yaml: "", error: i18n.t("decoders:wizard.err.timeFormat") };
    if (lay?.noYear) return { yaml: "", error: i18n.t("decoders:wizard.err.noYear") };
    L.push("time:", `  fields: [${timeSources.join(", ")}]`, `  layout: ${q(st.timeLayout)}`);
    if (st.timeZone) {
      if (!/^[A-Za-z]+(\/[A-Za-z0-9_+-]+)*$|^UTC$/.test(st.timeZone)) return { yaml: "", error: i18n.t("decoders:wizard.err.zone") };
      L.push(`  timezone: ${q(st.timeZone)}`);
    }
  }
  const samples = st.samples.slice(0, 10);
  if (samples.length) {
    L.push("samples:");
    for (const s of samples) L.push(`  - ${q(s)}`);
  }
  return { yaml: L.join("\n") + "\n" };
}

// patternRegexes: wyrażenia wzorców w kolejności (parser bierze pierwszy pasujący).
export function patternRegexes(st: Pick<WizardState, "patterns" | "timeLayout">): BuiltPattern[] {
  const lay = LAYOUTS.find((l) => l.value === st.timeLayout);
  return st.patterns.map((p) => {
    const layouts: Record<string, Layout | undefined> = {};
    for (const sp of p.spans) if (sp.key === "time") layouts[groupName(sp)] = lay;
    for (let i = 2; i < 6; i++) layouts[`time${i}`] = lay;
    return buildRegex(p.msg, p.spans, layouts);
  });
}

// Propozycje id i zbioru z nazwy programu albo hosta.
export function slug(s: string): string {
  return s
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
}
