// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState } from "react";
import { Badge, Card, Group, SimpleGrid, Stack, Text, ThemeIcon, Title } from "@mantine/core";
import { IconActivityHeartbeat, IconAlertTriangle, IconArchive, IconBolt, IconDatabaseSearch, IconDeviceDesktop } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
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
import { statusColors } from "./SystemPage";
import { useAuth } from "../auth";

export default function HomePage() {
  const { t } = useTranslation("home");
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
      .catch(() => setDb(t("dbDown")));
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
        <Title order={2}>{t("welcome", { name: user?.display_name || user?.username })}</Title>
        <Text c="dimmed">{t("intro")}</Text>
      </div>

      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
        <Card withBorder component={Link} to="/alerts">
          <Group mb="xs">
            <ThemeIcon variant="light" size="lg" color={alertSum && alertSum.open > 0 ? "orange" : undefined}>
              <IconAlertTriangle size={20} />
            </ThemeIcon>
            <Text fw={600}>{t("alertsTitle")}</Text>
          </Group>
          {alertSum ? (
            <Group gap="xs">
              <Badge variant="light" color={alertSum.open > 0 ? "orange" : "green"}>
                {t("open", { count: alertSum.open })}
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
              {t("noData")}
            </Text>
          )}
        </Card>
        <Card withBorder component={Link} to="/agents">
          <Group mb="xs">
            <ThemeIcon variant="light" size="lg">
              <IconDeviceDesktop size={20} />
            </ThemeIcon>
            <Text fw={600}>{t("agentsTitle")}</Text>
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
                {t("withProblems", { count: fleet.with_problems })}
              </Badge>
            </Group>
          ) : (
            <Text size="sm" c="dimmed">
              {t("noData")}
            </Text>
          )}
        </Card>
        <Card withBorder component={Link} to="/archive">
          <Group mb="xs">
            <ThemeIcon variant="light" size="lg">
              <IconArchive size={20} />
            </ThemeIcon>
            <Text fw={600}>{t("archiveTitle")}</Text>
          </Group>
          {archive ? (
            <Badge color={complianceLabels[archive.compliance].color} variant="light">
              {complianceLabels[archive.compliance].label}
            </Badge>
          ) : (
            <Text size="sm" c="dimmed">
              {t("noData")}
            </Text>
          )}
        </Card>
        <Card withBorder component={Link} to="/system">
          <Group mb="xs">
            <ThemeIcon variant="light" size="lg" color={system ? statusColors[system.overall] : undefined}>
              <IconActivityHeartbeat size={20} />
            </ThemeIcon>
            <Text fw={600}>{t("systemTitle")}</Text>
          </Group>
          <Group gap="xs">
            {system ? (
              <Badge color={statusColors[system.overall]} variant="light">
                {system.overall === "ok" ? t("allOk") : t("needsAttention", { count: problems })}
              </Badge>
            ) : (
              <Badge color="gray" variant="light">
                {t("noData")}
              </Badge>
            )}
            <Badge color={db === "ok" ? "green" : "red"} variant="light">
              {t("db", { status: db === "ok" ? t("dbOk") : db })}
            </Badge>
          </Group>
        </Card>
      </SimpleGrid>

      <SimpleGrid cols={{ base: 1, sm: 2 }}>
        {[
          { to: "/events", name: "Mímir", what: t("eventsWhat"), icon: IconDatabaseSearch },
          { to: "/deploy", name: "Bifröst", what: t("deployWhat"), icon: IconBolt },
        ].map((m) => (
          <Card key={m.to} withBorder component={Link} to={m.to}>
            <Group mb="xs">
              <ThemeIcon variant="light" size="lg">
                <m.icon size={20} />
              </ThemeIcon>
              <Text fw={600}>{m.name}</Text>
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
