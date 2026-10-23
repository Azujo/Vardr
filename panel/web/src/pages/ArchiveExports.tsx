// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Anchor,
  Badge,
  Button,
  Card,
  CopyButton,
  Group,
  MultiSelect,
  SimpleGrid,
  Stack,
  Table,
  TagsInput,
  Text,
  TextInput,
  Textarea,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconDownload, IconFileExport } from "@tabler/icons-react";
import {
  agentsApi,
  exportStatusLabels,
  exportsApi,
  formatBytes,
  formatDate,
  formatNumber,
  groupsApi,
  type AgentGroup,
  type AgentView,
  type ArchiveExport,
} from "../api";
import { useTranslation } from "react-i18next";
import { locale } from "../i18n";

// Wartość dla <input type="datetime-local"> (czas lokalny, pełna godzina).
function localHour(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:00`;
}

function hourRange(from: string, to: string) {
  const opt: Intl.DateTimeFormatOptions = { dateStyle: "short", timeStyle: "short" };
  return `${new Date(from).toLocaleString(locale(), opt)} – ${new Date(to).toLocaleString(locale(), opt)}`;
}

// Eksport dla audytora (tylko administrator): zlecenie, stan i pobranie paczki.
export default function ArchiveExports() {
  const { t } = useTranslation("archive");
  const [from, setFrom] = useState(() => localHour(new Date(Date.now() - 24 * 3600_000)));
  const [to, setTo] = useState(() => localHour(new Date()));
  const [reason, setReason] = useState("");
  const [selGroups, setSelGroups] = useState<string[]>([]);
  const [selAgents, setSelAgents] = useState<string[]>([]);
  const [groups, setGroups] = useState<AgentGroup[]>([]);
  const [agents, setAgents] = useState<AgentView[]>([]);
  const [busy, setBusy] = useState(false);
  const [items, setItems] = useState<ArchiveExport[]>([]);
  const [downloads, setDownloads] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    exportsApi
      .list()
      .then((r) => {
        setItems(r.exports);
        setDownloads(r.downloads);
        setError("");
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);
  useEffect(() => {
    groupsApi
      .list()
      .then((r) => setGroups(r.groups))
      .catch(() => {});
    agentsApi
      .list()
      .then((r) => setAgents(r.agents))
      .catch(() => {});
  }, []);
  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await exportsApi.create({
        from: new Date(from).toISOString(),
        to: new Date(to).toISOString(),
        reason,
        agents: selAgents,
        groups: selGroups.map(Number),
      });
      notifications.show({ color: "green", message: t("export.requested") });
      setReason("");
      load();
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack>
      <Card withBorder>
        <form onSubmit={submit}>
          <Stack gap="sm">
            <Group gap="xs">
              <IconFileExport size={20} />
              <Title order={4}>{t("tab.exports")}</Title>
            </Group>
            <Text size="sm" c="dimmed">
              {t("export.intro")}
            </Text>
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <TextInput
                type="datetime-local"
                label={t("from")}
                required
                value={from}
                onChange={(e) => setFrom(e.currentTarget.value)}
              />
              <TextInput
                type="datetime-local"
                label={t("to")}
                required
                value={to}
                onChange={(e) => setTo(e.currentTarget.value)}
              />
            </SimpleGrid>
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <MultiSelect
                label={t("export.groups")}
                data={groups.map((g) => ({ value: String(g.id), label: t("groupOption", { name: g.name, n: g.agents }) }))}
                value={selGroups}
                onChange={setSelGroups}
                searchable
                clearable
              />
              <TagsInput
                label={t("export.agents")}
                data={agents.map((a) => ({ value: a.id, label: `${a.id} (${a.hostname})` }))}
                value={selAgents}
                onChange={setSelAgents}
                clearable
              />
            </SimpleGrid>
            <Text size="xs" c="dimmed">
              {t("export.selectionHint")}
            </Text>
            <Textarea
              label={t("export.reason")}
              description={t("export.reasonHint")}
              required
              minLength={5}
              maxLength={1000}
              autosize
              minRows={2}
              value={reason}
              onChange={(e) => setReason(e.currentTarget.value)}
            />
            <Group>
              <Button type="submit" loading={busy} leftSection={<IconFileExport size={18} />}>
                {t("export.submit")}
              </Button>
            </Group>
          </Stack>
        </form>
      </Card>

      {error && <Alert color="red">{error}</Alert>}
      {!downloads && (
        <Alert color="orange">
          {t("export.downloadsOff")}
        </Alert>
      )}
      {items.length > 0 && (
        <Table.ScrollContainer minWidth={900}>
          <Table striped verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr style={{ whiteSpace: "nowrap" }}>
                <Table.Th>{t("manifest.no")}</Table.Th>
                <Table.Th>{t("col.range")}</Table.Th>
                <Table.Th>{t("col.byReason")}</Table.Th>
                <Table.Th>{t("col.state")}</Table.Th>
                <Table.Th>{t("export.content")}</Table.Th>
                <Table.Th>{t("export.sha")}</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((x) => (
                <Table.Tr key={x.id}>
                  <Table.Td>{x.id}</Table.Td>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>{hourRange(x.from, x.to)}</Table.Td>
                  <Table.Td maw={260}>
                    <Text size="sm">{x.requested_by}</Text>
                    <Text size="xs" c="dimmed" lineClamp={2} title={x.reason}>
                      {x.reason}
                    </Text>
                    {x.agents?.length > 0 && (
                      <Text size="xs" c="dimmed" lineClamp={1} title={x.agents.join(", ")}>
                        {t("export.agentsList", { list: x.agents.join(", ") })}
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    <Tooltip label={x.error || formatDate(x.finished_at ?? x.requested_at)} multiline maw={400}>
                      <Badge color={exportStatusLabels[x.status].color} variant="light">
                        {exportStatusLabels[x.status].label}
                      </Badge>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>
                    {x.status === "done" || x.status === "expired" ? (
                      <Text size="sm">
                        {t("export.contentValue", { h: x.manifests, n: formatNumber(x.records), size: formatBytes(x.bytes) })}
                      </Text>
                    ) : (
                      <Text size="sm" c="dimmed">
                        —
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    {x.sha256 ? (
                      <CopyButton value={x.sha256}>
                        {({ copied, copy }) => (
                          <Tooltip label={copied ? t("copied") : x.sha256} multiline maw={600}>
                            <Text size="xs" ff="monospace" c="dimmed" style={{ cursor: "pointer" }} onClick={copy}>
                              {x.sha256?.slice(0, 16)}…
                            </Text>
                          </Tooltip>
                        )}
                      </CopyButton>
                    ) : (
                      "—"
                    )}
                  </Table.Td>
                  <Table.Td>
                    {x.status === "done" && downloads && (
                      <Anchor href={exportsApi.downloadUrl(x.id)} size="sm">
                        <Group gap={4} wrap="nowrap">
                          <IconDownload size={16} /> {t("export.download")}
                        </Group>
                      </Anchor>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Stack>
  );
}
