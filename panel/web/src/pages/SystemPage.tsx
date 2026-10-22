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
import { formatDate, systemApi, type SystemCheck, type SystemReport } from "../api";

export const statusLabels: Record<string, { label: string; color: string }> = {
  ok: { label: "OK", color: "green" },
  off: { label: "wyłączone", color: "gray" },
  unknown: { label: "brak danych", color: "gray" },
  warn: { label: "uwaga", color: "orange" },
  crit: { label: "problem", color: "red" },
};

// Linki do Grafany (pulpity z deploy/lab/grafana/dashboards, alerty
// z provisioning/alerting) – żeby przy awarii nie szukać adresów.
const grafanaRanges: Record<string, string> = { "1h": "1 h", "6h": "6 h", "24h": "24 h", "7d": "7 dni" };

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
  Potok: undefined,
  Usługi: 6,
  Serwer: 40,
};

function groupLink(base: string, group: string, range: string): string {
  if (group in groupPanels) return dash(base, "siem-pipeline", range, groupPanels[group]);
  // Pozostałe grupy (detekcja, archiwum, kopie) – reguły alertów Grafany z tej dziedziny.
  const words: Record<string, string> = { Detekcja: "detek", "Archiwum NIS2": "archiw", "Kopie zapasowe": "kopi" };
  return `${base}/alerting/list?search=${encodeURIComponent(words[group] ?? group)}`;
}

function GrafanaLinks({ base, range, setRange }: { base: string; range: string; setRange: (r: string) => void }) {
  const links = [
    { label: "Zdrowie potoku", icon: IconTimeline, href: dash(base, "siem-pipeline", range), hint: "przepływ, kolejki, opóźnienia, CPU i pamięć usług" },
    { label: "Przegląd zdarzeń", icon: IconChartLine, href: dash(base, "siem-overview", range), hint: "zdarzenia, agenci, logowania" },
    { label: "Alerty – aktywne", icon: IconAlertTriangle, href: `${base}/alerting/list?search=${encodeURIComponent("state:firing")}`, hint: "co teraz alarmuje w Grafanie" },
    { label: "Reguły alertów", icon: IconBell, href: `${base}/alerting/list`, hint: "wszystkie reguły i ich stan" },
    { label: "Explore (Prometheus)", icon: IconListSearch, href: `${base}/explore`, hint: "własne zapytania do metryk" },
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
          data={Object.entries(grafanaRanges).map(([value, label]) => ({ value, label }))}
        />
      </Group>
      <Group gap="xs">
        {links.map((l) => (
          <Button
            key={l.label}
            component="a"
            href={l.href}
            target="_blank"
            rel="noopener noreferrer"
            variant="light"
            size="sm"
            leftSection={<l.icon size={16} />}
            rightSection={<IconExternalLink size={12} />}
            title={l.hint}
          >
            {l.label}
          </Button>
        ))}
      </Group>
    </Card>
  );
}

// Himinbjörg – stan systemu: zdrowie usług z metryk Prometheusa.
export default function SystemPage() {
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

  const groups: { name: string; checks: SystemCheck[] }[] = [];
  for (const c of report?.checks ?? []) {
    let g = groups.find((x) => x.name === c.group);
    if (!g) {
      g = { name: c.group, checks: [] };
      groups.push(g);
    }
    g.checks.push(c);
  }
  const problems = (report?.checks ?? []).filter((c) => c.status === "warn" || c.status === "crit");

  return (
    <Stack>
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>Himinbjörg – stan systemu</Title>
          <Text c="dimmed" size="sm">
            Zdrowie usług Vardra z metryk (Prometheus), odświeżane co 30 s. Szczegółowe wykresy i alerty – linki do Grafany niżej.
          </Text>
        </div>
        {report && (
          <Group gap="xs">
            <IconActivityHeartbeat size={20} />
            <Badge size="lg" color={statusLabels[report.overall].color}>
              {report.overall === "ok" ? "wszystko działa" : statusLabels[report.overall].label}
            </Badge>
            <Text size="xs" c="dimmed">
              {formatDate(report.generated_at)}
            </Text>
          </Group>
        )}
      </Group>
      {error && <MAlert color="red">{error}</MAlert>}
      {grafana && <GrafanaLinks base={grafana} range={range} setRange={setRange} />}
      {!configured && <MAlert color="gray">siem-api nie ma adresu Prometheusa (SIEM_PROMETHEUS_URL) – stan systemu niedostępny.</MAlert>}
      {problems.length > 0 && (
        <MAlert color={problems.some((c) => c.status === "crit") ? "red" : "orange"} title={`Wymaga uwagi (${problems.length})`}>
          <Stack gap={4}>
            {problems.map((c) => (
              <Text size="sm" key={c.name}>
                <b>{c.name}</b>: {c.value}
                {c.hint ? ` – ${c.hint}` : ""}
                {grafana && (
                  <>
                    {" "}
                    <Anchor href={groupLink(grafana, c.group, range)} target="_blank" rel="noopener noreferrer" size="sm">
                      wykresy w Grafanie
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
          <Card withBorder key={g.name}>
            <Group justify="space-between" mb="xs">
              <Title order={4}>{g.name}</Title>
              {grafana && (
                <Anchor href={groupLink(grafana, g.name, range)} target="_blank" rel="noopener noreferrer" size="xs">
                  <Group gap={4}>
                    Grafana <IconExternalLink size={12} />
                  </Group>
                </Anchor>
              )}
            </Group>
            <Table verticalSpacing={4} fz="sm">
              <Table.Tbody>
                {g.checks.map((c) => (
                  <Table.Tr key={c.name}>
                    <Table.Td w={110}>
                      <Badge size="sm" variant="light" color={statusLabels[c.status]?.color ?? "gray"}>
                        {statusLabels[c.status]?.label ?? c.status}
                      </Badge>
                    </Table.Td>
                    <Table.Td>{c.name}</Table.Td>
                    <Table.Td ta="right" c="dimmed" style={{ whiteSpace: "nowrap" }}>
                      {c.value}
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
