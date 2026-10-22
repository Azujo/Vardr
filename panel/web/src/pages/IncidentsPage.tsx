// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import { Alert, Badge, Button, Group, SegmentedControl, Stack, Table, Text, Title } from "@mantine/core";
import { IconPlus } from "@tabler/icons-react";
import { Link, useNavigate } from "react-router-dom";
import { formatDate, incidentSeverityLabels, incidentStatusLabels, incidentsApi, type Incident, type IncidentDeadline } from "../api";
import { useAuth } from "../auth";
import { DeadlineBadge, nextDeadline } from "../incidents";
import AddToIncident from "./AddToIncident";

export default function IncidentsPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const [scope, setScope] = useState("active");
  const [items, setItems] = useState<(Incident & { deadlines: IncidentDeadline[] })[]>([]);
  const [now, setNow] = useState(Date.now());
  const [error, setError] = useState("");
  const [creating, setCreating] = useState(false);

  const load = useCallback(() => {
    incidentsApi
      .list(scope)
      .then((r) => {
        setItems(r.incidents);
        setNow(new Date(r.now).getTime());
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [scope]);
  useEffect(load, [load]);
  useEffect(() => {
    const t = setInterval(() => setNow((n) => n + 60000), 60000);
    return () => clearInterval(t);
  }, []);

  return (
    <Stack>
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>Incydenty</Title>
          <Text c="dimmed" size="sm" maw={820}>
            Incydent łączy alerty, ustalenia i działania w jedną historię. Incydent poważny w rozumieniu NIS2 ma terminy
            zgłoszeń do CSIRT: wczesne ostrzeżenie w 24 h od stwierdzenia, zgłoszenie w 72 h, sprawozdanie końcowe w miesiąc.
          </Text>
        </div>
        {can("incidents", "write") && (
          <Button leftSection={<IconPlus size={16} />} onClick={() => setCreating(true)}>
            Nowy incydent
          </Button>
        )}
      </Group>
      <SegmentedControl
        w="fit-content"
        value={scope}
        onChange={setScope}
        data={[
          { value: "active", label: "Aktywne" },
          { value: "closed", label: "Zamknięte" },
          { value: "all", label: "Wszystkie" },
        ]}
      />
      {error && <Alert color="red">{error}</Alert>}
      {items.length === 0 && !error && (
        <Text c="dimmed" size="sm">
          Brak incydentów w tym widoku. Incydent założysz tu albo z listy alertów (zaznacz alerty → „Do incydentu”).
        </Text>
      )}
      {items.length > 0 && (
        <Table.ScrollContainer minWidth={900}>
          <Table striped highlightOnHover verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>#</Table.Th>
                <Table.Th>Incydent</Table.Th>
                <Table.Th>Waga</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>NIS2</Table.Th>
                <Table.Th>Alerty</Table.Th>
                <Table.Th>Prowadzi</Table.Th>
                <Table.Th>Zmiana</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((x) => {
                const next = nextDeadline(x.deadlines);
                return (
                  <Table.Tr key={x.id} style={{ cursor: "pointer" }} onClick={() => navigate(`/incidents/${x.id}`)}>
                    <Table.Td>{x.id}</Table.Td>
                    <Table.Td maw={380}>
                      <Text component={Link} to={`/incidents/${x.id}`} size="sm" fw={500} onClick={(e) => e.stopPropagation()}>
                        {x.title}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge color={incidentSeverityLabels[x.severity].color}>{incidentSeverityLabels[x.severity].label}</Badge>
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="light" color={incidentStatusLabels[x.status].color}>
                        {incidentStatusLabels[x.status].label}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      {x.significant ? (
                        next ? (
                          <DeadlineBadge d={next} now={now} />
                        ) : (
                          <Badge color="green" variant="light">
                            zgłoszenia wysłane
                          </Badge>
                        )
                      ) : (
                        <Text size="xs" c="dimmed">
                          —
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>{x.alert_count}</Table.Td>
                    <Table.Td>{x.assignee || "—"}</Table.Td>
                    <Table.Td>
                      <Text size="xs">{formatDate(x.updated_at)}</Text>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      <AddToIncident alertIds={[]} opened={creating} onClose={() => setCreating(false)} />
    </Stack>
  );
}
