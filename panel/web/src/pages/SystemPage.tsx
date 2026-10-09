import { useCallback, useEffect, useState } from "react";
import { Alert as MAlert, Badge, Card, Group, SimpleGrid, Stack, Table, Text, Title } from "@mantine/core";
import { IconActivityHeartbeat } from "@tabler/icons-react";
import { formatDate, systemApi, type SystemCheck, type SystemReport } from "../api";

export const statusLabels: Record<string, { label: string; color: string }> = {
  ok: { label: "OK", color: "green" },
  off: { label: "wyłączone", color: "gray" },
  unknown: { label: "brak danych", color: "gray" },
  warn: { label: "uwaga", color: "orange" },
  crit: { label: "problem", color: "red" },
};

// Himinbjörg – stan systemu: zdrowie usług z metryk Prometheusa.
export default function SystemPage() {
  const [report, setReport] = useState<SystemReport | null>(null);
  const [configured, setConfigured] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    systemApi
      .get()
      .then((r) => {
        setConfigured(r.configured);
        setReport(r.report ?? null);
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
            Zdrowie usług Heimdalla z metryk (Prometheus), odświeżane co 30 s. Szczegółowe wykresy – Grafana.
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
      {!configured && <MAlert color="gray">siem-api nie ma adresu Prometheusa (SIEM_PROMETHEUS_URL) – stan systemu niedostępny.</MAlert>}
      {problems.length > 0 && (
        <MAlert color={problems.some((c) => c.status === "crit") ? "red" : "orange"} title={`Wymaga uwagi (${problems.length})`}>
          <Stack gap={4}>
            {problems.map((c) => (
              <Text size="sm" key={c.name}>
                <b>{c.name}</b>: {c.value}
                {c.hint ? ` – ${c.hint}` : ""}
              </Text>
            ))}
          </Stack>
        </MAlert>
      )}
      <SimpleGrid cols={{ base: 1, md: 2 }}>
        {groups.map((g) => (
          <Card withBorder key={g.name}>
            <Title order={4} mb="xs">
              {g.name}
            </Title>
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
