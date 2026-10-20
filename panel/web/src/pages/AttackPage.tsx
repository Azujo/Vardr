import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Anchor,
  Badge,
  Box,
  Button,
  Card,
  Drawer,
  Group,
  Loader,
  ScrollArea,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { IconDownload, IconExternalLink, IconSearch } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { levelLabels, type AlertLevel } from "../api";
import {
  attackApi,
  parentOf,
  techniqueURL,
  useAttackDict,
  type AttackTechnique,
  type CoverageRule,
} from "../attack";

// Komórka macierzy: technika nadrzędna z regułami jej i jej podtechnik.
interface Cell {
  t: AttackTechnique;
  rules: CoverageRule[]; // reguły tej techniki albo jej podtechnik (bez reguł bazowych korelacji)
  enabled: number;
  alerts: number;
  subs: AttackTechnique[];
  subsCovered: number;
}

type State = "alerts" | "covered" | "disabled" | "none";

const stateStyle: Record<State, { bg: string; border: string; label: string }> = {
  alerts: { bg: "var(--mantine-color-orange-light)", border: "var(--mantine-color-orange-6)", label: "pokryta, były alerty" },
  covered: { bg: "var(--mantine-color-green-light)", border: "var(--mantine-color-green-6)", label: "pokryta włączoną regułą" },
  disabled: { bg: "var(--mantine-color-yellow-light)", border: "var(--mantine-color-yellow-6)", label: "tylko wyłączone reguły" },
  none: { bg: "transparent", border: "var(--mantine-color-default-border)", label: "bez reguł" },
};

function cellState(c: Cell): State {
  if (c.enabled === 0) return c.rules.length > 0 ? "disabled" : "none";
  return c.alerts > 0 ? "alerts" : "covered";
}

// Platformy, które zbiera Vardr (Windows, Entra ID, urządzenia sieciowe).
const platforms = [
  { value: "", label: "wszystkie platformy" },
  { value: "Windows", label: "Windows" },
  { value: "Identity Provider", label: "Entra ID / dostawca tożsamości" },
  { value: "Network Devices", label: "urządzenia sieciowe" },
  { value: "SaaS", label: "SaaS" },
  { value: "IaaS", label: "chmura (IaaS)" },
  { value: "Linux", label: "Linux" },
];

function sinceParam(days: number): string {
  return days <= 1 ? "24h" : days <= 7 ? "7d" : days <= 30 ? "30d" : "";
}

export default function AttackPage() {
  const dict = useAttackDict();
  const [days, setDays] = useState("30");
  const [rules, setRules] = useState<CoverageRule[] | null>(null);
  const [error, setError] = useState("");
  const [view, setView] = useState("all");
  const [platform, setPlatform] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<Cell | null>(null);

  useEffect(() => {
    setRules(null);
    attackApi
      .coverage(Number(days))
      .then((r) => {
        setRules(r.rules);
        setError("");
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [days]);

  const { columns, stats, warnings } = useMemo(() => {
    const empty = { columns: [] as { tactic: { id: string; short: string; name: string }; cells: Cell[]; covered: number; total: number }[], stats: { covered: 0, total: 0, alerts: 0 }, warnings: [] as { rule: CoverageRule; w: string }[] };
    if (!dict || !rules) return empty;
    // Reguły na technikę (bez reguł bazowych korelacji – same nie alarmują).
    const byTech = new Map<string, CoverageRule[]>();
    const warns: { rule: CoverageRule; w: string }[] = [];
    for (const r of rules) {
      for (const w of r.warnings ?? []) warns.push({ rule: r, w });
      if (r.correlation_only) continue;
      for (const id of r.techniques) {
        if (!byTech.has(id)) byTech.set(id, []);
        byTech.get(id)!.push(r);
      }
    }
    const subsOf = new Map<string, AttackTechnique[]>();
    for (const t of dict.techniques) {
      if (t.deprecated || !t.id.includes(".")) continue;
      const p = parentOf(t.id);
      if (!subsOf.has(p)) subsOf.set(p, []);
      subsOf.get(p)!.push(t);
    }
    const cellOf = new Map<string, Cell>();
    for (const t of dict.techniques) {
      if (t.deprecated || t.id.includes(".")) continue;
      const subs = subsOf.get(t.id) ?? [];
      const rs = new Map<string, CoverageRule>();
      for (const r of byTech.get(t.id) ?? []) rs.set(r.id, r);
      let subsCovered = 0;
      for (const s of subs) {
        const sr = byTech.get(s.id) ?? [];
        if (sr.some((r) => r.enabled)) subsCovered++;
        for (const r of sr) rs.set(r.id, r);
      }
      const list = [...rs.values()];
      cellOf.set(t.id, {
        t,
        rules: list,
        enabled: list.filter((r) => r.enabled).length,
        alerts: list.reduce((n, r) => n + r.alerts.total, 0),
        subs,
        subsCovered,
      });
    }
    const needle = q.trim().toLowerCase();
    const cols = dict.tactics.map((tactic) => {
      const all = [...cellOf.values()].filter((c) => c.t.tactics.includes(tactic.short));
      const shown = all
        .filter((c) => !platform || (c.t.platforms ?? []).includes(platform))
        .filter((c) => view === "all" || c.rules.length > 0)
        .filter((c) => !needle || c.t.name.toLowerCase().includes(needle) || c.t.id.toLowerCase().includes(needle))
        .sort((a, b) => Number(b.rules.length > 0) - Number(a.rules.length > 0) || a.t.name.localeCompare(b.t.name));
      return { tactic, cells: shown, covered: all.filter((c) => c.enabled > 0).length, total: all.length };
    });
    const parents = [...cellOf.values()].filter((c) => !platform || (c.t.platforms ?? []).includes(platform));
    return {
      columns: cols,
      stats: {
        covered: parents.filter((c) => c.enabled > 0).length,
        total: parents.length,
        alerts: rules.filter((r) => !r.correlation_only).reduce((n, r) => n + r.alerts.total, 0),
      },
      warnings: warns,
    };
  }, [dict, rules, view, platform, q]);

  const since = sinceParam(Number(days));
  const alertsLink = (technique: string) => `/alerts?status=all&technique=${encodeURIComponent(technique)}${since ? `&since=${since}` : ""}`;

  return (
    <Stack>
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>MITRE ATT&CK – pokrycie</Title>
          <Text c="dimmed" size="sm" maw={900}>
            Techniki ATT&CK {dict?.version ?? ""} według tagów reguł (<code>attack.t…</code>). Kolor komórki: czy technikę wykrywa włączona
            reguła i czy w wybranym okresie były alerty. Technika obejmuje swoje podtechniki. Kliknij komórkę, żeby zobaczyć reguły
            i alerty.
          </Text>
        </div>
        <Button
          component="a"
          href={attackApi.navigatorURL(Number(days))}
          variant="light"
          leftSection={<IconDownload size={16} />}
          title="Warstwa dla MITRE ATT&CK Navigator: techniki pokryte włączonymi regułami, wynik = liczba alertów"
        >
          Eksport do ATT&CK Navigator
        </Button>
      </Group>
      {error && <Alert color="red">{error}</Alert>}
      {(!dict || !rules) && !error && <Loader />}
      {dict && rules && (
        <>
          <SimpleGrid cols={{ base: 1, sm: 3 }}>
            <Card withBorder padding="sm">
              <Text size="xs" c="dimmed">
                Techniki pokryte włączonymi regułami
              </Text>
              <Text fz={24} fw={700}>
                {stats.covered} / {stats.total}
              </Text>
              <Text size="xs" c="dimmed">
                {platform ? `platforma: ${platform}` : "wszystkie platformy"} · {((100 * stats.covered) / Math.max(1, stats.total)).toFixed(1)}%
              </Text>
            </Card>
            <Card withBorder padding="sm">
              <Text size="xs" c="dimmed">
                Taktyki z co najmniej jedną regułą
              </Text>
              <Text fz={24} fw={700}>
                {columns.filter((c) => c.covered > 0).length} / {columns.length}
              </Text>
              <Text size="xs" c="dimmed" lineClamp={2}>
                bez reguł:{" "}
                {columns
                  .filter((c) => c.covered === 0)
                  .map((c) => c.tactic.name)
                  .join(", ") || "—"}
              </Text>
            </Card>
            <Card withBorder padding="sm">
              <Text size="xs" c="dimmed">
                Alerty z reguł z technikami ATT&CK ({days} dni)
              </Text>
              <Text fz={24} fw={700}>
                {stats.alerts}
              </Text>
              <Text size="xs" c="dimmed">
                {rules.filter((r) => r.techniques.length === 0 && !r.correlation_only).length} reguł bez techniki ATT&CK
              </Text>
            </Card>
          </SimpleGrid>

          {warnings.length > 0 && (
            <Alert color="orange" title={`Tagi do poprawy (${warnings.length})`}>
              {warnings.slice(0, 10).map((x, i) => (
                <Text size="sm" key={i}>
                  <b>{x.rule.title}</b>: {x.w}
                </Text>
              ))}
            </Alert>
          )}

          <Group gap="xs" wrap="wrap">
            <SegmentedControl
              size="xs"
              value={days}
              onChange={setDays}
              data={[
                { value: "7", label: "7 dni" },
                { value: "30", label: "30 dni" },
                { value: "90", label: "90 dni" },
              ]}
            />
            <SegmentedControl
              size="xs"
              value={view}
              onChange={setView}
              data={[
                { value: "all", label: "wszystkie techniki" },
                { value: "covered", label: "tylko z regułami" },
              ]}
            />
            <Select size="xs" w={240} allowDeselect={false} value={platform} onChange={(v) => setPlatform(v ?? "")} data={platforms} />
            <TextInput
              size="xs"
              w={220}
              placeholder="szukaj techniki"
              leftSection={<IconSearch size={14} />}
              value={q}
              onChange={(e) => setQ(e.currentTarget.value)}
            />
            <Group gap={6} ml="auto">
              {(Object.keys(stateStyle) as State[]).map((s) => (
                <Group key={s} gap={4}>
                  <Box w={14} h={14} style={{ background: stateStyle[s].bg, border: `1px solid ${stateStyle[s].border}`, borderRadius: 3 }} />
                  <Text size="xs">{stateStyle[s].label}</Text>
                </Group>
              ))}
            </Group>
          </Group>

          <ScrollArea type="auto" offsetScrollbars>
            <Group align="flex-start" gap={6} wrap="nowrap">
              {columns.map((col) => (
                <Stack key={col.tactic.id} gap={4} w={168} style={{ flex: "0 0 168px" }}>
                  <Tooltip label={`${col.tactic.id} – pokryte ${col.covered} z ${col.total} technik`}>
                    <Box
                      p={6}
                      style={{
                        background: "var(--mantine-color-grape-light)",
                        borderRadius: 4,
                        minHeight: 52,
                      }}
                    >
                      <Text size="xs" fw={700} lh={1.2}>
                        {col.tactic.name}
                      </Text>
                      <Text size="xs" c="dimmed">
                        {col.covered}/{col.total}
                      </Text>
                    </Box>
                  </Tooltip>
                  {col.cells.map((c) => {
                    const st = stateStyle[cellState(c)];
                    return (
                      <Box
                        key={c.t.id}
                        p={5}
                        onClick={() => setOpen(c)}
                        style={{
                          background: st.bg,
                          border: `1px solid ${st.border}`,
                          borderRadius: 4,
                          cursor: "pointer",
                        }}
                        title={`${c.t.id} ${c.t.name}`}
                      >
                        <Text size="xs" lh={1.2} fw={c.rules.length ? 600 : 400}>
                          {c.t.name}
                        </Text>
                        <Group gap={4} justify="space-between">
                          <Text size="10px" c="dimmed">
                            {c.t.id}
                          </Text>
                          {(c.rules.length > 0 || c.subs.length > 0) && (
                            <Text size="10px" c="dimmed">
                              {c.rules.length > 0 ? `${c.enabled} reg.` : ""}
                              {c.alerts > 0 ? ` · ${c.alerts} al.` : ""}
                              {c.subs.length > 0 && c.subsCovered > 0 ? ` · ${c.subsCovered}/${c.subs.length} pod.` : ""}
                            </Text>
                          )}
                        </Group>
                      </Box>
                    );
                  })}
                </Stack>
              ))}
            </Group>
          </ScrollArea>
        </>
      )}

      <Drawer opened={!!open} onClose={() => setOpen(null)} position="right" size="lg" title={open ? `${open.t.id} ${open.t.name}` : ""}>
        {open && dict && (
          <Stack gap="sm">
            <Group gap="xs">
              {open.t.tactics.map((s) => (
                <Badge key={s} variant="outline" color="grape">
                  {dict.tactics.find((t) => t.short === s)?.name ?? s}
                </Badge>
              ))}
              <Anchor href={techniqueURL(open.t.id)} target="_blank" rel="noopener noreferrer" size="sm">
                opis w MITRE ATT&CK <IconExternalLink size={12} />
              </Anchor>
            </Group>
            {open.t.platforms && (
              <Text size="xs" c="dimmed">
                Platformy: {open.t.platforms.join(", ")}
              </Text>
            )}
            <Text fw={600} size="sm">
              Reguły ({open.rules.length})
            </Text>
            {open.rules.length === 0 ? (
              <Text size="sm" c="dimmed">
                Żadna reguła nie ma tagu tej techniki ani jej podtechnik. Nowa reguła: Reguły detekcji → Przetestuj nową regułę albo
                kreator korelacji; tag <code>attack.{open.t.id.toLowerCase()}</code>.
              </Text>
            ) : (
              <Table fz="sm" verticalSpacing={4}>
                <Table.Tbody>
                  {open.rules.map((r) => (
                    <Table.Tr key={r.id} style={{ opacity: r.enabled ? 1 : 0.55 }}>
                      <Table.Td>
                        <Badge size="sm" color={levelLabels[r.level as AlertLevel]?.color}>
                          {levelLabels[r.level as AlertLevel]?.label ?? r.level}
                        </Badge>
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm">{r.title}</Text>
                        <Text size="xs" c="dimmed">
                          {r.techniques.join(", ")} · {r.enabled ? "włączona" : "wyłączona"} · {r.file}
                        </Text>
                      </Table.Td>
                      <Table.Td ta="right" style={{ whiteSpace: "nowrap" }}>
                        {r.alerts.total > 0 ? (
                          <Anchor component={Link} to={`/alerts?status=all&rule=${encodeURIComponent(r.id)}${since ? `&since=${since}` : ""}`} size="sm">
                            {r.alerts.total} alertów ({r.alerts.open} otw.)
                          </Anchor>
                        ) : (
                          <Text size="xs" c="dimmed">
                            bez alertów
                          </Text>
                        )}
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}
            {open.alerts > 0 && (
              <Button component={Link} to={alertsLink(open.t.id)} variant="light" size="xs" w="fit-content">
                Alerty tej techniki ({days} dni)
              </Button>
            )}
            {open.subs.length > 0 && (
              <>
                <Text fw={600} size="sm">
                  Podtechniki ({open.subsCovered}/{open.subs.length} pokrytych)
                </Text>
                <Stack gap={2}>
                  {open.subs.map((s) => {
                    const n = open.rules.filter((r) => r.enabled && r.techniques.includes(s.id)).length;
                    return (
                      <Group key={s.id} gap="xs" wrap="nowrap">
                        <Badge size="xs" variant={n ? "filled" : "outline"} color={n ? "green" : "gray"} w={64}>
                          {s.id}
                        </Badge>
                        <Anchor href={techniqueURL(s.id)} target="_blank" rel="noopener noreferrer" size="sm" c={n ? undefined : "dimmed"}>
                          {s.name}
                        </Anchor>
                        {n > 0 && (
                          <Text size="xs" c="dimmed">
                            {n} reg.
                          </Text>
                        )}
                      </Group>
                    );
                  })}
                </Stack>
              </>
            )}
          </Stack>
        )}
      </Drawer>
    </Stack>
  );
}
