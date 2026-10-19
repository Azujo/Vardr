// MITRE ATT&CK w panelu: słownik (z serwera, raz na sesję), odczyt tagów
// reguł (attack.t1110.001, attack.credential_access) i plakietki technik.
import { useEffect, useState } from "react";
import { Anchor, Badge, Group, Text, Tooltip } from "@mantine/core";
import { request, type RuleAttack, type RuleAttribution } from "./api";

export interface AttackTactic {
  id: string;
  short: string;
  name: string;
}

export interface AttackTechnique {
  id: string;
  name: string;
  tactics: string[];
  platforms?: string[];
  deprecated?: boolean;
  replaced_by?: string;
}

export interface AttackDict {
  version: string;
  tactics: AttackTactic[];
  techniques: AttackTechnique[];
  byId: Map<string, AttackTechnique>;
}

export interface CoverageRule {
  id: string;
  title: string;
  level: string;
  mode: string;
  file: string;
  enabled: boolean;
  correlation_only?: boolean;
  techniques: string[];
  alerts: { total: number; open: number; last?: string };
  warnings?: string[];
}

export const attackApi = {
  dictionary: () =>
    request<{ version: string; tactics: AttackTactic[]; techniques: AttackTechnique[] }>("GET", "/api/v1/attack/dictionary"),
  coverage: (days: number) =>
    request<{ version: string; days: number; rules: CoverageRule[] }>("GET", `/api/v1/attack/coverage?days=${days}`),
  navigatorURL: (days: number) => `/api/v1/attack/navigator?days=${days}`,
};

let dictPromise: Promise<AttackDict> | null = null;

function loadDict(): Promise<AttackDict> {
  if (!dictPromise) {
    dictPromise = attackApi
      .dictionary()
      .then((d) => ({ ...d, byId: new Map(d.techniques.map((t) => [t.id, t])) }))
      .catch((e) => {
        dictPromise = null;
        throw e;
      });
  }
  return dictPromise;
}

// useAttackDict: słownik ATT&CK (null do czasu wczytania albo przy błędzie).
export function useAttackDict(): AttackDict | null {
  const [d, setD] = useState<AttackDict | null>(null);
  useEffect(() => {
    let live = true;
    loadDict()
      .then((x) => live && setD(x))
      .catch(() => live && setD(null));
    return () => {
      live = false;
    };
  }, []);
  return d;
}

export function techniqueURL(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}

export function parentOf(id: string): string {
  const i = id.indexOf(".");
  return i > 0 ? id.slice(0, i) : id;
}

// mapTags: techniki i taktyki z tagów reguły (jak internal/attack.Map).
export function mapTags(d: AttackDict, tags: string[]): RuleAttack & { warnings: string[] } {
  const out: RuleAttack & { warnings: string[] } = { techniques: [], tactics: [], warnings: [] };
  const tactics = new Set<string>();
  for (const raw of tags) {
    const tag = raw.trim().toLowerCase();
    const m = /^attack\.(t\d{4}(?:\.\d{3})?)$/.exec(tag);
    if (m) {
      const t = d.byId.get(m[1].toUpperCase());
      if (!t) {
        out.warnings.push(`${raw}: nieznana technika`);
        continue;
      }
      if (t.deprecated) out.warnings.push(`${raw}: wycofana${t.replaced_by ? ` – zastąpiona przez ${t.replaced_by}` : ""}`);
      if (!out.techniques.some((x) => x.id === t.id)) out.techniques.push({ id: t.id, name: t.name, url: techniqueURL(t.id) });
      t.tactics.forEach((x) => tactics.add(x));
      continue;
    }
    if (/^attack\.[gs]\d{4}$/.test(tag) || !tag.startsWith("attack.")) continue;
    const short = tag.slice(7).replace(/_/g, "-");
    if (d.tactics.some((t) => t.short === short)) tactics.add(short);
  }
  for (const t of d.tactics) {
    if (tactics.has(t.short)) out.tactics.push({ id: t.id, name: t.name, url: `https://attack.mitre.org/tactics/${t.id}/` });
  }
  return out;
}

// Plakietki technik (z linkiem do MITRE) i – opcjonalnie – taktyk.
export function AttackBadges({ ra, tactics = true, size = "sm" }: { ra?: RuleAttack; tactics?: boolean; size?: "xs" | "sm" }) {
  if (!ra || ra.techniques.length + ra.tactics.length === 0) return null;
  return (
    <Group gap={4} wrap="wrap" onClick={(e) => e.stopPropagation()}>
      {tactics &&
        ra.tactics.map((t) => (
          <Badge key={t.id} size={size} variant="outline" color="grape" title={`taktyka ${t.id}`}>
            {t.name}
          </Badge>
        ))}
      {ra.techniques.map((t) => (
        <Tooltip key={t.id} label={`${t.id} ${t.name} – opis w MITRE ATT&CK`}>
          <Anchor href={t.url} target="_blank" rel="noopener noreferrer" underline="never">
            <Badge size={size} variant="light" color="grape" style={{ cursor: "pointer", textTransform: "none" }}>
              {t.id} {t.name}
            </Badge>
          </Anchor>
        </Tooltip>
      ))}
    </Group>
  );
}

// Plakietki z tagów reguły (strona reguł – słownik po stronie przeglądarki).
export function AttackTags({ tags, size = "sm" }: { tags: string[]; size?: "xs" | "sm" }) {
  const d = useAttackDict();
  if (!d) return null;
  return <AttackBadges ra={mapTags(d, tags)} size={size} />;
}

// Autor i źródło reguły z SigmaHQ (licencja DRL 1.1).
export function AttributionLine({ a }: { a?: RuleAttribution }) {
  if (!a) return null;
  return (
    <Text size="xs" c="dimmed">
      Autor reguły: {a.author} · źródło:{" "}
      <Anchor href={a.rule_url} target="_blank" rel="noopener noreferrer" size="xs">
        {a.source}
      </Anchor>{" "}
      · licencja{" "}
      <Anchor href={a.license_url} target="_blank" rel="noopener noreferrer" size="xs">
        {a.license}
      </Anchor>
    </Text>
  );
}
