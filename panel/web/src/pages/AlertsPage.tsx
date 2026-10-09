import { useCallback, useEffect, useState } from "react";
import { Alert as MAlert, Badge, Button, Group, SegmentedControl, Select, Stack, Table, Text, Title } from "@mantine/core";
import { IconAlertTriangle } from "@tabler/icons-react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ago, alertStatusLabels, alertsApi, formatDate, levelLabels, type Alert, type AlertLevel } from "../api";

// Gjallarhorn – lista alertów (najnowsze pierwsze).
export default function AlertsPage() {
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "open";
  const level = params.get("level") ?? "";
  const rule = params.get("rule") ?? "";
  const [items, setItems] = useState<Alert[]>([]);
  const [configured, setConfigured] = useState(true);
  const [error, setError] = useState("");
  const [more, setMore] = useState(false);
  const navigate = useNavigate();

  const load = useCallback(
    (before?: number) => {
      alertsApi
        .list({ status: status === "all" ? "" : status, level, rule, before })
        .then((r) => {
          setConfigured(r.configured);
          setItems((cur) => (before ? [...cur, ...r.alerts] : r.alerts));
          setMore(r.alerts.length === 100);
          setError("");
        })
        .catch((e) => setError(e instanceof Error ? e.message : String(e)));
    },
    [status, level, rule],
  );
  useEffect(() => {
    load();
    const t = setInterval(() => load(), 15000);
    return () => clearInterval(t);
  }, [load]);

  const set = (k: string, v: string) => {
    const p = new URLSearchParams(params);
    if (v) p.set(k, v);
    else p.delete(k);
    setParams(p);
  };

  return (
    <Stack>
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>Gjallarhorn – alerty</Title>
          <Text c="dimmed" size="sm">
            Alerty z reguł detekcji (Sigma). Trafienia z tym samym kluczem (np. komputer i polecenie) w oknie reguły łączą się
            w jeden alert z licznikiem.{" "}
            <Text span component={Link} to="/rules" c="blue" size="sm">
              Reguły →
            </Text>
          </Text>
        </div>
        <Group>
          <SegmentedControl
            value={status}
            onChange={(v) => set("status", v === "open" ? "" : v)}
            data={[
              { value: "open", label: "otwarte" },
              { value: "acknowledged", label: "w analizie" },
              { value: "closed", label: "zamknięte" },
              { value: "all", label: "wszystkie" },
            ]}
          />
          <Select
            placeholder="każdy poziom"
            clearable
            w={160}
            value={level || null}
            onChange={(v) => set("level", v ?? "")}
            data={(Object.keys(levelLabels) as AlertLevel[]).reverse().map((l) => ({ value: l, label: levelLabels[l].label }))}
          />
        </Group>
      </Group>
      {error && <MAlert color="red">{error}</MAlert>}
      {!configured && (
        <MAlert color="gray" icon={<IconAlertTriangle />}>
          Detektor (siem-detector) jeszcze nie działał – nie ma alertów ani reguł.
        </MAlert>
      )}
      {configured && items.length === 0 && (
        <Text c="dimmed" size="sm">
          Brak alertów w tym widoku.
        </Text>
      )}
      {items.length > 0 && (
        <Table.ScrollContainer minWidth={900}>
          <Table striped highlightOnHover verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr style={{ whiteSpace: "nowrap" }}>
                <Table.Th>Poziom</Table.Th>
                <Table.Th>Reguła</Table.Th>
                <Table.Th>Komputer</Table.Th>
                <Table.Th>Konto</Table.Th>
                <Table.Th>Trafienia</Table.Th>
                <Table.Th>Ostatnie zdarzenie</Table.Th>
                <Table.Th>Stan</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((a) => (
                <Table.Tr key={a.id} style={{ cursor: "pointer" }} onClick={() => navigate(`/alerts/${a.id}`)}>
                  <Table.Td>
                    <Badge color={levelLabels[a.level].color}>{levelLabels[a.level].label}</Badge>
                  </Table.Td>
                  <Table.Td maw={420}>
                    <Text size="sm" fw={500}>
                      {a.rule_title}
                    </Text>
                    <Text size="xs" c="dimmed" lineClamp={1} title={a.summary}>
                      {a.summary}
                    </Text>
                  </Table.Td>
                  <Table.Td>{a.host_name || "—"}</Table.Td>
                  <Table.Td>{a.user_name || "—"}</Table.Td>
                  <Table.Td>{a.hits}</Table.Td>
                  <Table.Td style={{ whiteSpace: "nowrap" }} title={formatDate(a.last_seen)}>
                    {ago(a.last_seen)}
                  </Table.Td>
                  <Table.Td>
                    <Badge variant="light" color={alertStatusLabels[a.status].color}>
                      {alertStatusLabels[a.status].label}
                    </Badge>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      {more && (
        <Group>
          <Button variant="subtle" onClick={() => load(items[items.length - 1].id)}>
            Starsze alerty
          </Button>
        </Group>
      )}
    </Stack>
  );
}
