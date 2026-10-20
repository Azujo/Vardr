import { useEffect, useState } from "react";
import { Badge, Card, Group, SimpleGrid, Stack, Text, ThemeIcon, Title } from "@mantine/core";
import { IconActivityHeartbeat, IconAlertTriangle, IconArchive, IconBolt, IconDatabaseSearch, IconDeviceDesktop } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import {
  agentsApi,
  alertsApi,
  api,
  archiveApi,
  complianceLabels,
  levelLabels,
  systemApi,
  type AgentsSummary,
  type AlertLevel,
  type AlertsSummary,
  type ArchiveOverview,
  type SystemReport,
} from "../api";
import { statusLabels } from "./SystemPage";
import { useAuth } from "../auth";

export default function HomePage() {
  const { user } = useAuth();
  const [db, setDb] = useState<string>("…");
  const [fleet, setFleet] = useState<AgentsSummary | null>(null);
  const [archive, setArchive] = useState<ArchiveOverview | null>(null);
  const [alertSum, setAlertSum] = useState<AlertsSummary | null>(null);
  const [system, setSystem] = useState<SystemReport | null>(null);

  useEffect(() => {
    api
      .health()
      .then((h) => setDb(h.database))
      .catch(() => setDb("niedostępna"));
    agentsApi
      .list()
      .then((r) => setFleet(r.summary))
      .catch(() => setFleet(null));
    archiveApi
      .overview()
      .then(setArchive)
      .catch(() => setArchive(null));
    alertsApi
      .summary()
      .then((r) => setAlertSum(r.summary ?? null))
      .catch(() => setAlertSum(null));
    systemApi
      .get()
      .then((r) => setSystem(r.report ?? null))
      .catch(() => setSystem(null));
  }, []);
  const problems = system?.checks.filter((c) => c.status === "warn" || c.status === "crit").length ?? 0;

  return (
    <Stack>
      <div>
        <Title order={2}>Witaj, {user?.display_name || user?.username}</Title>
        <Text c="dimmed">Vardr czuwa – tu widać, co dzieje się w sieci.</Text>
      </div>

      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
        <Card withBorder component={Link} to="/alerts">
          <Group mb="xs">
            <ThemeIcon variant="light" size="lg" color={alertSum && alertSum.open > 0 ? "orange" : undefined}>
              <IconAlertTriangle size={20} />
            </ThemeIcon>
            <Text fw={600}>Gjallarhorn – otwarte alerty</Text>
          </Group>
          {alertSum ? (
            <Group gap="xs">
              <Badge variant="light" color={alertSum.open > 0 ? "orange" : "green"}>
                otwarte: {alertSum.open}
              </Badge>
              {(["critical", "high", "medium", "low", "informational"] as AlertLevel[])
                .filter((l) => alertSum.open_by_level[l])
                .map((l) => (
                  <Badge key={l} color={levelLabels[l].color} variant="light">
                    {levelLabels[l].label}: {alertSum.open_by_level[l]}
                  </Badge>
                ))}
            </Group>
          ) : (
            <Text size="sm" c="dimmed">
              brak danych
            </Text>
          )}
        </Card>
        <Card withBorder component={Link} to="/agents">
          <Group mb="xs">
            <ThemeIcon variant="light" size="lg">
              <IconDeviceDesktop size={20} />
            </ThemeIcon>
            <Text fw={600}>Huginn – agenci</Text>
          </Group>
          {fleet ? (
            <Group gap="xs">
              <Badge color="green" variant="light">
                online: {fleet.online}
              </Badge>
              <Badge color="gray" variant="light">
                offline: {fleet.offline}
              </Badge>
              <Badge color={fleet.with_problems ? "orange" : "gray"} variant="light">
                z problemami: {fleet.with_problems}
              </Badge>
            </Group>
          ) : (
            <Text size="sm" c="dimmed">
              brak danych
            </Text>
          )}
        </Card>
        <Card withBorder component={Link} to="/archive">
          <Group mb="xs">
            <ThemeIcon variant="light" size="lg">
              <IconArchive size={20} />
            </ThemeIcon>
            <Text fw={600}>Urd – archiwum NIS2</Text>
          </Group>
          {archive ? (
            <Badge color={complianceLabels[archive.compliance].color} variant="light">
              {complianceLabels[archive.compliance].label}
            </Badge>
          ) : (
            <Text size="sm" c="dimmed">
              brak danych
            </Text>
          )}
        </Card>
        <Card withBorder component={Link} to="/system">
          <Group mb="xs">
            <ThemeIcon variant="light" size="lg" color={system ? statusLabels[system.overall].color : undefined}>
              <IconActivityHeartbeat size={20} />
            </ThemeIcon>
            <Text fw={600}>Himinbjörg – stan systemu</Text>
          </Group>
          <Group gap="xs">
            {system ? (
              <Badge color={statusLabels[system.overall].color} variant="light">
                {system.overall === "ok" ? "wszystko działa" : `wymaga uwagi: ${problems}`}
              </Badge>
            ) : (
              <Badge color="gray" variant="light">
                brak danych
              </Badge>
            )}
            <Badge color={db === "ok" ? "green" : "red"} variant="light">
              baza Saga: {db}
            </Badge>
          </Group>
        </Card>
      </SimpleGrid>

      <SimpleGrid cols={{ base: 1, sm: 2 }}>
        {[
          { to: "/events", name: "Mímir", what: "zdarzenia – wyszukiwanie, histogram i szczegóły z surowym XML", icon: IconDatabaseSearch, soon: false },
          { to: "/deploy", name: "Bifröst", what: "wdrażanie agentów tokenem i paczki instalacyjne", icon: IconBolt, soon: false },
        ].map((m) => (
          <Card key={m.to} withBorder component={Link} to={m.to}>
            <Group mb="xs">
              <ThemeIcon variant="light" size="lg">
                <m.icon size={20} />
              </ThemeIcon>
              <Text fw={600}>{m.name}</Text>
              {m.soon && (
                <Badge size="xs" variant="light" color="gray">
                  w budowie
                </Badge>
              )}
            </Group>
            <Text size="sm" c="dimmed">
              {m.what}
            </Text>
          </Card>
        ))}
      </SimpleGrid>
    </Stack>
  );
}
