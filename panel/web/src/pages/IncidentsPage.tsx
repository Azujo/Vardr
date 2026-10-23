// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import { Alert, Badge, Button, Group, SegmentedControl, Stack, Table, Text, Title } from "@mantine/core";
import { IconPlus } from "@tabler/icons-react";
import { Link, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { formatDate, incidentSeverityColors, incidentStatusColors, incidentsApi, type Incident, type IncidentDeadline } from "../api";
import { useAuth } from "../auth";
import { DeadlineBadge, nextDeadline } from "../incidents";
import AddToIncident from "./AddToIncident";

export default function IncidentsPage() {
  const { t } = useTranslation("incidents");
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
          <Title order={2}>{t("list.title")}</Title>
          <Text c="dimmed" size="sm" maw={820}>
            {t("list.intro")}
          </Text>
        </div>
        {can("incidents", "write") && (
          <Button leftSection={<IconPlus size={16} />} onClick={() => setCreating(true)}>
            {t("list.new")}
          </Button>
        )}
      </Group>
      <SegmentedControl
        w="fit-content"
        value={scope}
        onChange={setScope}
        data={[
          { value: "active", label: t("list.active") },
          { value: "closed", label: t("list.closed") },
          { value: "all", label: t("list.all") },
        ]}
      />
      {error && <Alert color="red">{error}</Alert>}
      {items.length === 0 && !error && (
        <Text c="dimmed" size="sm">
          {t("list.empty")}
        </Text>
      )}
      {items.length > 0 && (
        <Table.ScrollContainer minWidth={900}>
          <Table striped highlightOnHover verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>#</Table.Th>
                <Table.Th>{t("list.colIncident")}</Table.Th>
                <Table.Th>{t("list.colSeverity")}</Table.Th>
                <Table.Th>{t("list.colStatus")}</Table.Th>
                <Table.Th>{t("list.colNis2")}</Table.Th>
                <Table.Th>{t("list.colAlerts")}</Table.Th>
                <Table.Th>{t("list.colAssignee")}</Table.Th>
                <Table.Th>{t("list.colChanged")}</Table.Th>
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
                      <Badge color={incidentSeverityColors[x.severity]}>{t(`severity.${x.severity}`)}</Badge>
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="light" color={incidentStatusColors[x.status]}>
                        {t(`status.${x.status}`)}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      {x.significant ? (
                        next ? (
                          <DeadlineBadge d={next} now={now} />
                        ) : (
                          <Badge color="green" variant="light">
                            {t("list.allSubmitted")}
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
