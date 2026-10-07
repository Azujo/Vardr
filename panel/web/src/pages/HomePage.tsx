import { useEffect, useState } from "react";
import { Badge, Card, Group, SimpleGrid, Stack, Text, ThemeIcon, Title } from "@mantine/core";
import { IconBolt, IconDatabaseSearch, IconDeviceDesktop, IconServer } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";

const modules = [
  { to: "/agents", name: "Huginn", what: "agenci na komputerach – lista, stan, heartbeat", icon: IconDeviceDesktop },
  { to: "/events", name: "Mímir", what: "zdarzenia – wyszukiwanie i szczegóły", icon: IconDatabaseSearch },
  { to: "/deploy", name: "Bifröst", what: "wdrażanie agentów tokenem", icon: IconBolt },
];

export default function HomePage() {
  const { user } = useAuth();
  const [db, setDb] = useState<string>("…");

  useEffect(() => {
    api
      .health()
      .then((h) => setDb(h.database))
      .catch(() => setDb("niedostępna"));
  }, []);

  return (
    <Stack>
      <div>
        <Title order={2}>Witaj, {user?.display_name || user?.username}</Title>
        <Text c="dimmed">Heimdall strzeże mostu – tu widać, co dzieje się w sieci.</Text>
      </div>

      <Card withBorder>
        <Group>
          <ThemeIcon variant="light" size="lg">
            <IconServer size={20} />
          </ThemeIcon>
          <div>
            <Text fw={500}>Stan panelu</Text>
            <Group gap="xs">
              <Text size="sm" c="dimmed">
                Baza Saga:
              </Text>
              <Badge color={db === "ok" ? "green" : "red"} variant="light">
                {db}
              </Badge>
            </Group>
          </div>
        </Group>
      </Card>

      <SimpleGrid cols={{ base: 1, sm: 3 }}>
        {modules.map((m) => (
          <Card key={m.to} withBorder component={Link} to={m.to}>
            <Group mb="xs">
              <ThemeIcon variant="light" size="lg">
                <m.icon size={20} />
              </ThemeIcon>
              <Text fw={600}>{m.name}</Text>
              <Badge size="xs" variant="light" color="gray">
                w budowie
              </Badge>
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
