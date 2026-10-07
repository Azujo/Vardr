import { useEffect, useState } from "react";
import { Badge, Card, Group, SimpleGrid, Stack, Text, ThemeIcon, Title } from "@mantine/core";
import { IconBolt, IconDatabaseSearch, IconDeviceDesktop, IconServer } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { agentsApi, api, type AgentsSummary } from "../api";
import { useAuth } from "../auth";

export default function HomePage() {
  const { user } = useAuth();
  const [db, setDb] = useState<string>("…");
  const [fleet, setFleet] = useState<AgentsSummary | null>(null);

  useEffect(() => {
    api
      .health()
      .then((h) => setDb(h.database))
      .catch(() => setDb("niedostępna"));
    agentsApi
      .list()
      .then((r) => setFleet(r.summary))
      .catch(() => setFleet(null));
  }, []);

  return (
    <Stack>
      <div>
        <Title order={2}>Witaj, {user?.display_name || user?.username}</Title>
        <Text c="dimmed">Heimdall strzeże mostu – tu widać, co dzieje się w sieci.</Text>
      </div>

      <SimpleGrid cols={{ base: 1, sm: 2 }}>
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
        <Card withBorder>
          <Group mb="xs">
            <ThemeIcon variant="light" size="lg">
              <IconServer size={20} />
            </ThemeIcon>
            <Text fw={600}>Stan panelu</Text>
          </Group>
          <Group gap="xs">
            <Text size="sm" c="dimmed">
              Baza Saga:
            </Text>
            <Badge color={db === "ok" ? "green" : "red"} variant="light">
              {db}
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
