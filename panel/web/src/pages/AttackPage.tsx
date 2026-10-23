// SPDX-License-Identifier: AGPL-3.0-or-later

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
import { useTranslation } from "react-i18next";
import { levelLabels, ruleText, type AlertLevel } from "../api";
import { locale } from "../i18n";
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

// Opisy stanów: attack: state.<stan>.
const stateStyle: Record<State, { bg: string; border: string }> = {
  alerts: { bg: "var(--mantine-color-orange-light)", border: "var(--mantine-color-orange-6)" },
  covered: { bg: "var(--mantine-color-green-light)", border: "var(--mantine-color-green-6)" },
  disabled: { bg: "var(--mantine-color-yellow-light)", border: "var(--mantine-color-yellow-6)" },
  none: { bg: "transparent", border: "var(--mantine-color-default-border)" },
};

function cellState(c: Cell): State {
  if (c.enabled === 0) return c.rules.length > 0 ? "disabled" : "none";
  return c.alerts > 0 ? "alerts" : "covered";
}

// Platformy, które zbiera Vardr (Windows, Entra ID, urządzenia sieciowe);
// nazwy: attack: platform.<klucz>.
const platforms = [
  { value: "", key: "all" },
  { value: "Windows", key: "windows" },
  { value: "Identity Provider", key: "idp" },
  { value: "Network Devices", key: "network" },
  { value: "SaaS", key: "saas" },
  { value: "IaaS", key: "iaas" },
  { value: "Linux", key: "linux" },
];

function sinceParam(days: number): string {
  return days <= 1 ? "24h" : days <= 7 ? "7d" : days <= 30 ? "30d" : "";
}

export default function AttackPage() {
  const { t: tr } = useTranslation("attack");
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
      for (const w of (locale() !== "pl" && r.warnings_en) || r.warnings || []) warns.push({ rule: r, w });
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
          <Title order={2}>{tr("title")}</Title>
          <Text c="dimmed" size="sm" maw={900}>
            {tr("intro", { version: dict?.version ?? "" })}
          </Text>
        </div>
        <Button
          component="a"
          href={attackApi.navigatorURL(Number(days))}
          variant="light"
          leftSection={<IconDownload size={16} />}
          title={tr("exportHint")}
        >
          {tr("export")}
        </Button>
      </Group>
      {error && <Alert color="red">{error}</Alert>}
      {(!dict || !rules) && !error && <Loader />}
      {dict && rules && (
        <>
          <SimpleGrid cols={{ base: 1, sm: 3 }}>
            <Card withBorder padding="sm">
              <Text size="xs" c="dimmed">
                {tr("stats.covered")}
              </Text>
              <Text fz={24} fw={700}>
                {stats.covered} / {stats.total}
              </Text>
              <Text size="xs" c="dimmed">
                {platform ? tr("stats.platform", { platform }) : tr("platform.all")} · {((100 * stats.covered) / Math.max(1, stats.total)).toFixed(1)}%
              </Text>
            </Card>
            <Card withBorder padding="sm">
              <Text size="xs" c="dimmed">
                {tr("stats.tactics")}
              </Text>
              <Text fz={24} fw={700}>
                {columns.filter((c) => c.covered > 0).length} / {columns.length}
              </Text>
              <Text size="xs" c="dimmed" lineClamp={2}>
                {tr("stats.noRules")}{" "}
                {columns
                  .filter((c) => c.covered === 0)
                  .map((c) => c.tactic.name)
                  .join(", ") || "—"}
              </Text>
            </Card>
            <Card withBorder padding="sm">
              <Text size="xs" c="dimmed">
                {tr("stats.alerts", { days })}
              </Text>
              <Text fz={24} fw={700}>
                {stats.alerts}
              </Text>
              <Text size="xs" c="dimmed">
                {tr("stats.untagged", { count: rules.filter((r) => r.techniques.length === 0 && !r.correlation_only).length })}
              </Text>
            </Card>
          </SimpleGrid>

          {warnings.length > 0 && (
            <Alert color="orange" title={tr("warnings", { count: warnings.length })}>
              {warnings.slice(0, 10).map((x, i) => (
                <Text size="sm" key={i}>
                  <b>{ruleText(x.rule).title}</b>: {x.w}
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
                { value: "7", label: tr("days", { n: 7 }) },
                { value: "30", label: tr("days", { n: 30 }) },
                { value: "90", label: tr("days", { n: 90 }) },
              ]}
            />
            <SegmentedControl
              size="xs"
              value={view}
              onChange={setView}
              data={[
                { value: "all", label: tr("view.all") },
                { value: "covered", label: tr("view.covered") },
              ]}
            />
            <Select size="xs" w={240} allowDeselect={false} value={platform} onChange={(v) => setPlatform(v ?? "")}
              data={platforms.map((p) => ({ value: p.value, label: p.value === "Windows" || p.value === "SaaS" || p.value === "Linux" ? p.value : tr(`platform.${p.key}`) }))}
            />
            <TextInput
              size="xs"
              w={220}
              placeholder={tr("search")}
              leftSection={<IconSearch size={14} />}
              value={q}
              onChange={(e) => setQ(e.currentTarget.value)}
            />
            <Group gap={6} ml="auto">
              {(Object.keys(stateStyle) as State[]).map((s) => (
                <Group key={s} gap={4}>
                  <Box w={14} h={14} style={{ background: stateStyle[s].bg, border: `1px solid ${stateStyle[s].border}`, borderRadius: 3 }} />
                  <Text size="xs">{tr(`state.${s}`)}</Text>
                </Group>
              ))}
            </Group>
          </Group>

          <ScrollArea type="auto" offsetScrollbars>
            <Group align="flex-start" gap={6} wrap="nowrap">
              {columns.map((col) => (
                <Stack key={col.tactic.id} gap={4} w={168} style={{ flex: "0 0 168px" }}>
                  <Tooltip label={tr("tacticTip", { id: col.tactic.id, covered: col.covered, total: col.total })}>
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
                              {c.rules.length > 0 ? tr("cell.rules", { n: c.enabled }) : ""}
                              {c.alerts > 0 ? ` · ${tr("cell.alerts", { n: c.alerts })}` : ""}
                              {c.subs.length > 0 && c.subsCovered > 0 ? ` · ${tr("cell.subs", { n: c.subsCovered, total: c.subs.length })}` : ""}
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
                  {dict.tactics.find((x) => x.short === s)?.name ?? s}
                </Badge>
              ))}
              <Anchor href={techniqueURL(open.t.id)} target="_blank" rel="noopener noreferrer" size="sm">
                {tr("mitreLink")} <IconExternalLink size={12} />
              </Anchor>
            </Group>
            {open.t.platforms && (
              <Text size="xs" c="dimmed">
                {tr("platforms", { list: open.t.platforms.join(", ") })}
              </Text>
            )}
            <Text fw={600} size="sm">
              {tr("rules", { count: open.rules.length })}
            </Text>
            {open.rules.length === 0 ? (
              <Text size="sm" c="dimmed">
                {tr("noRules", { tag: `attack.${open.t.id.toLowerCase()}` })}
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
                        <Text size="sm">{ruleText(r).title}</Text>
                        <Text size="xs" c="dimmed">
                          {r.techniques.join(", ")} · {r.enabled ? tr("enabled") : tr("disabled")} · {r.file}
                        </Text>
                      </Table.Td>
                      <Table.Td ta="right" style={{ whiteSpace: "nowrap" }}>
                        {r.alerts.total > 0 ? (
                          <Anchor component={Link} to={`/alerts?status=all&rule=${encodeURIComponent(r.id)}${since ? `&since=${since}` : ""}`} size="sm">
                            {tr("ruleAlerts", { total: r.alerts.total, open: r.alerts.open })}
                          </Anchor>
                        ) : (
                          <Text size="xs" c="dimmed">
                            {tr("noAlerts")}
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
                {tr("techniqueAlerts", { days })}
              </Button>
            )}
            {open.subs.length > 0 && (
              <>
                <Text fw={600} size="sm">
                  {tr("subtechniques", { n: open.subsCovered, total: open.subs.length })}
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
                            {tr("cell.rules", { n })}
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
