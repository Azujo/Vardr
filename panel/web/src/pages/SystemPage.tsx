// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import {
  Alert as MAlert,
  Anchor,
  Badge,
  Button,
  Card,
  Group,
  SegmentedControl,
  SimpleGrid,
  Stack,
  Table,
  Text,
  Title,
} from "@mantine/core";
import {
  IconActivityHeartbeat,
  IconAlertTriangle,
  IconBell,
  IconChartLine,
  IconExternalLink,
  IconListSearch,
  IconTimeline,
} from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { ago, formatDate, formatNumber, systemApi, type SystemCheck, type SystemReport } from "../api";

// Kolory stanów; nazwy – system: status.*.
export const statusColors: Record<string, string> = {
  ok: "green",
  off: "gray",
  unknown: "gray",
  warn: "orange",
  crit: "red",
};

type T = TFunction<"system">;

// Kontrola w języku użytkownika: serwer podaje identyfikatory i wartość jako
// kod z parametrami; nieznany kod (nowsza kontrola) – polski tekst z serwera.
function checkName(t: T, c: SystemCheck): string {
  return c.id ? t(`check.${c.id}`, { defaultValue: c.name }) : c.name;
}

function checkHint(t: T, c: SystemCheck): string {
  if (!c.hint) return "";
  return c.id ? t(`hint.${c.id}`, { defaultValue: c.hint, error: c.args?.error ?? "" }) : c.hint;
}

function groupName(t: T, c: SystemCheck): string {
  return c.group_id ? t(`group.${c.group_id}`, { defaultValue: c.group }) : c.group;
}

function checkValue(t: T, c: SystemCheck): string {
  if (!c.value_key) return c.value;
  const n = Number(c.args?.n ?? 0);
  const args = { n: formatNumber(n), count: n, consumer: c.args?.consumer ?? "", defaultValue: c.value };
  if (c.value_key === "ago") return ago(new Date(Date.now() - n * 1000).toISOString());
  return t(`value.${c.value_key}`, args);
}

// Linki do Grafany (pulpity z deploy/lab/grafana/dashboards, alerty
// z provisioning/alerting) – żeby przy awarii nie szukać adresów.
const grafanaRanges = ["1h", "6h", "24h", "7d"];

function grafanaBase(url?: string): string {
  if (url) return url;
  // Bez SIEM_GRAFANA_URL: Grafana na tym samym serwerze, port 3000 (lab).
  return `http://${window.location.hostname}:3000`;
}

function dash(base: string, uid: string, range: string, panel?: number): string {
  const p = new URLSearchParams({ from: `now-${range}`, to: "now", refresh: "30s" });
  if (panel) p.set("viewPanel", `panel-${panel}`);
  return `${base}/d/${uid}?${p.toString()}`;
}

// Wykresy dla grupy kontroli (pulpit „zdrowie potoku”, panel albo cały).
const groupPanels: Record<string, number | undefined> = {
  pipeline: undefined,
  services: 6,
  server: 40,
};

function groupLink(base: string, group: string, range: string): string {
  if (group in groupPanels) return dash(base, "siem-pipeline", range, groupPanels[group]);
  // Pozostałe grupy (detekcja, archiwum, kopie) – reguły alertów Grafany z tej
  // dziedziny (nazwy reguł w Grafanie są po polsku).
  const words: Record<string, string> = { detection: "detek", archive: "archiw", backup: "kopi" };
  return `${base}/alerting/list?search=${encodeURIComponent(words[group] ?? group)}`;
}

function GrafanaLinks({ base, range, setRange }: { base: string; range: string; setRange: (r: string) => void }) {
  const { t } = useTranslation("system");
  const links = [
    { key: "pipeline", icon: IconTimeline, href: dash(base, "siem-pipeline", range) },
    { key: "overview", icon: IconChartLine, href: dash(base, "siem-overview", range) },
    { key: "firing", icon: IconAlertTriangle, href: `${base}/alerting/list?search=${encodeURIComponent("state:firing")}` },
    { key: "rules", icon: IconBell, href: `${base}/alerting/list` },
    { key: "explore", icon: IconListSearch, href: `${base}/explore` },
  ];
  return (
    <Card withBorder>
      <Group justify="space-between" mb="xs">
        <Group gap="xs">
          <Title order={4}>Grafana</Title>
          <Anchor href={base} target="_blank" rel="noopener noreferrer" size="xs" c="dimmed">
            {base}
          </Anchor>
        </Group>
        <SegmentedControl
          size="xs"
          value={range}
          onChange={setRange}
          data={grafanaRanges.map((value) => ({ value, label: t(`range.${value}`) }))}
        />
      </Group>
      <Group gap="xs">
        {links.map((l) => (
          <Button
            key={l.key}
            component="a"
            href={l.href}
            target="_blank"
            rel="noopener noreferrer"
            variant="light"
            size="sm"
            leftSection={<l.icon size={16} />}
            rightSection={<IconExternalLink size={12} />}
            title={t(`grafana.${l.key}Hint`)}
          >
            {t(`grafana.${l.key}`)}
          </Button>
        ))}
      </Group>
    </Card>
  );
}

// Himinbjörg – stan systemu: zdrowie usług z metryk Prometheusa.
export default function SystemPage() {
  const { t } = useTranslation("system");
  const [report, setReport] = useState<SystemReport | null>(null);
  const [configured, setConfigured] = useState(true);
  const [error, setError] = useState("");
  const [grafana, setGrafana] = useState(() => grafanaBase());
  const [range, setRange] = useState("1h");

  const load = useCallback(() => {
    systemApi
      .get()
      .then((r) => {
        setConfigured(r.configured);
        setReport(r.report ?? null);
        setGrafana(grafanaBase(r.grafana_url));
        setError("");
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);
  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [load]);

  const groups: { id: string; name: string; checks: SystemCheck[] }[] = [];
  for (const c of report?.checks ?? []) {
    const id = c.group_id ?? c.group;
    let g = groups.find((x) => x.id === id);
    if (!g) {
      g = { id, name: groupName(t, c), checks: [] };
      groups.push(g);
    }
    g.checks.push(c);
  }
  const problems = (report?.checks ?? []).filter((c) => c.status === "warn" || c.status === "crit");

  return (
    <Stack>
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>{t("title")}</Title>
          <Text c="dimmed" size="sm">
            {t("intro")}
          </Text>
        </div>
        {report && (
          <Group gap="xs">
            <IconActivityHeartbeat size={20} />
            <Badge size="lg" color={statusColors[report.overall]}>
              {report.overall === "ok" ? t("allOk") : t(`status.${report.overall}`)}
            </Badge>
            <Text size="xs" c="dimmed">
              {formatDate(report.generated_at)}
            </Text>
          </Group>
        )}
      </Group>
      {error && <MAlert color="red">{error}</MAlert>}
      {grafana && <GrafanaLinks base={grafana} range={range} setRange={setRange} />}
      {!configured && <MAlert color="gray">{t("notConfigured")}</MAlert>}
      {problems.length > 0 && (
        <MAlert color={problems.some((c) => c.status === "crit") ? "red" : "orange"} title={t("attention", { count: problems.length })}>
          <Stack gap={4}>
            {problems.map((c) => (
              <Text size="sm" key={c.id ?? c.name}>
                <b>{checkName(t, c)}</b>: {checkValue(t, c)}
                {c.hint ? ` – ${checkHint(t, c)}` : ""}
                {grafana && (
                  <>
                    {" "}
                    <Anchor href={groupLink(grafana, c.group_id ?? c.group, range)} target="_blank" rel="noopener noreferrer" size="sm">
                      {t("charts")}
                    </Anchor>
                  </>
                )}
              </Text>
            ))}
          </Stack>
        </MAlert>
      )}
      <SimpleGrid cols={{ base: 1, md: 2 }}>
        {groups.map((g) => (
          <Card withBorder key={g.id}>
            <Group justify="space-between" mb="xs">
              <Title order={4}>{g.name}</Title>
              {grafana && (
                <Anchor href={groupLink(grafana, g.id, range)} target="_blank" rel="noopener noreferrer" size="xs">
                  <Group gap={4}>
                    Grafana <IconExternalLink size={12} />
                  </Group>
                </Anchor>
              )}
            </Group>
            <Table verticalSpacing={4} fz="sm">
              <Table.Tbody>
                {g.checks.map((c) => (
                  <Table.Tr key={c.id ?? c.name}>
                    <Table.Td w={110}>
                      <Badge size="sm" variant="light" color={statusColors[c.status] ?? "gray"}>
                        {t(`status.${c.status}`, { defaultValue: c.status })}
                      </Badge>
                    </Table.Td>
                    <Table.Td>{checkName(t, c)}</Table.Td>
                    <Table.Td ta="right" c="dimmed" style={{ whiteSpace: "nowrap" }}>
                      {checkValue(t, c)}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Card>
        ))}
      </SimpleGrid>
    </Stack>
  );
}
