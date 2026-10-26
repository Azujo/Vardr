// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import {
  Accordion,
  Alert,
  Anchor,
  Badge,
  Button,
  Card,
  Checkbox,
  Code,
  CopyButton,
  Group,
  List,
  NumberInput,
  PasswordInput,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Tabs,
  TagsInput,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAlertTriangle, IconCheck, IconCopy, IconDownload, IconEye } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { aiApi, formatDate, formatNumber, type AIPolicy, type AIRequest, type AIToolGroup } from "../api";
import { useAuth } from "../auth";

function errMsg(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

// Ostrzeżenia – zawsze widoczne na stronie i do potwierdzenia przy włączeniu.
export function AIWarnings() {
  const { t } = useTranslation("ai");
  return (
    <Alert color="orange" icon={<IconAlertTriangle />} title={t("warnings.title")}>
      <List size="sm" spacing={6}>
        {(["gdpr", "external", "hallucination", "injection", "decisions", "masking"] as const).map((k) => (
          <List.Item key={k}>
            <b>{t(`warnings.${k}.title`)}</b> {t(`warnings.${k}.text`)}
          </List.Item>
        ))}
      </List>
    </Alert>
  );
}

function Policy({ onSaved }: { onSaved: () => void }) {
  const { t } = useTranslation("ai");
  const { can } = useAuth();
  const canWrite = can("ai", "write");
  const [pol, setPol] = useState<AIPolicy | null>(null);
  const [tools, setTools] = useState<AIToolGroup[]>([]);
  const [acknowledged, setAcknowledged] = useState(false);
  const [ack, setAck] = useState(false);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const load = useCallback(() => {
    aiApi
      .policy()
      .then((r) => {
        setPol(r.policy);
        setTools(r.tools);
        setAcknowledged(r.acknowledged);
      })
      .catch((e) => setError(errMsg(e)));
  }, []);
  useEffect(load, [load]);
  if (error) return <Alert color="red">{error}</Alert>;
  if (!pol) return null;
  const needAck = pol.enabled && !acknowledged;
  const save = async () => {
    setBusy(true);
    try {
      await aiApi.setPolicy(pol, ack, password);
      notifications.show({ color: "green", message: t("policy.saved") });
      setPassword("");
      setAck(false);
      load();
      onSaved();
    } catch (e) {
      notifications.show({ color: "red", message: errMsg(e) });
    } finally {
      setBusy(false);
    }
  };
  const mask = pol.mask;
  return (
    <Card withBorder>
      <Stack>
        <Group justify="space-between">
          <Title order={4}>{t("policy.title")}</Title>
          {pol.ack_by && (
            <Text size="xs" c="dimmed">
              {t("policy.ackBy", { by: pol.ack_by, date: formatDate(pol.ack_at) })}
            </Text>
          )}
        </Group>
        <Switch
          size="md"
          disabled={!canWrite}
          label={t("policy.enabled")}
          description={t("policy.enabledHelp")}
          checked={pol.enabled}
          onChange={(e) => setPol({ ...pol, enabled: e.currentTarget.checked })}
        />
        <Text fw={600} size="sm">
          {t("policy.tools")}
        </Text>
        <SimpleGrid cols={{ base: 1, md: 2 }}>
          {tools.map((g) => (
            <Checkbox
              key={g.id}
              disabled={!canWrite}
              checked={!!pol.tools[g.id]}
              onChange={(e) => setPol({ ...pol, tools: { ...pol.tools, [g.id]: e.currentTarget.checked } })}
              label={
                <Group gap={6}>
                  {t(`tools.${g.id}.label`)}
                  {g.sensitive && (
                    <Badge size="xs" color="red" variant="light">
                      {t("policy.sensitive")}
                    </Badge>
                  )}
                </Group>
              }
              description={t(`tools.${g.id}.help`)}
            />
          ))}
        </SimpleGrid>
        <Text fw={600} size="sm">
          {t("policy.limits")}
        </Text>
        <Group grow align="flex-start">
          <NumberInput
            disabled={!canWrite}
            label={t("policy.maxRange")}
            description={t("policy.maxRangeHelp")}
            min={1}
            max={744}
            value={pol.max_range_hours}
            onChange={(v) => setPol({ ...pol, max_range_hours: typeof v === "number" ? v : 168 })}
          />
          <NumberInput
            disabled={!canWrite}
            label={t("policy.maxRows")}
            min={1}
            max={200}
            value={pol.max_rows}
            onChange={(v) => setPol({ ...pol, max_rows: typeof v === "number" ? v : 100 })}
          />
        </Group>
        <TagsInput
          disabled={!canWrite}
          label={t("policy.excluded")}
          description={t("policy.excludedHelp")}
          placeholder="hr.system, windows.powershell"
          value={pol.excluded_datasets ?? []}
          onChange={(v) => setPol({ ...pol, excluded_datasets: v })}
        />
        <Text fw={600} size="sm">
          {t("policy.masking")}
        </Text>
        <Text size="xs" c="dimmed">
          {t("policy.maskingHelp")}
        </Text>
        <Group>
          {(["users", "hosts", "ips", "emails"] as const).map((k) => (
            <Switch
              key={k}
              disabled={!canWrite}
              label={t(`mask.${k}`)}
              checked={mask[k]}
              onChange={(e) => setPol({ ...pol, mask: { ...mask, [k]: e.currentTarget.checked } })}
            />
          ))}
        </Group>
        {canWrite && (
          <>
            {needAck && (
              <Stack gap="xs">
                <AIWarnings />
                <Checkbox label={t("policy.ack")} checked={ack} onChange={(e) => setAck(e.currentTarget.checked)} />
              </Stack>
            )}
            <PasswordInput label={t("policy.password")} value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
            <Button loading={busy} disabled={!password || (needAck && !ack)} onClick={() => void save()}>
              {t("policy.save")}
            </Button>
          </>
        )}
      </Stack>
    </Card>
  );
}

function CopyLine({ value }: { value: string }) {
  const { t } = useTranslation("ai");
  return (
    <Group gap="xs" wrap="nowrap">
      <Code style={{ wordBreak: "break-all" }}>{value}</Code>
      <CopyButton value={value}>
        {({ copied, copy }) => (
          <Button size="compact-xs" variant="default" leftSection={copied ? <IconCheck size={12} /> : <IconCopy size={12} />} onClick={copy}>
            {copied ? t("copied") : t("copy")}
          </Button>
        )}
      </CopyButton>
    </Group>
  );
}

function CopyBlock({ value }: { value: string }) {
  const { t } = useTranslation("ai");
  return (
    <Group align="flex-start" wrap="nowrap">
      <Code block style={{ flex: 1 }}>
        {value}
      </Code>
      <CopyButton value={value}>
        {({ copied, copy }) => (
          <Button size="xs" variant="default" leftSection={copied ? <IconCheck size={14} /> : <IconCopy size={14} />} onClick={copy}>
            {copied ? t("copied") : t("copy")}
          </Button>
        )}
      </CopyButton>
    </Group>
  );
}

function Setup() {
  const { t } = useTranslation("ai");
  return (
    <Card withBorder>
      <Stack>
        <Title order={4}>{t("setup.title")}</Title>
        <Tabs defaultValue="desktop">
          <Tabs.List>
            <Tabs.Tab value="desktop">{t("setup.tabDesktop")}</Tabs.Tab>
            <Tabs.Tab value="remote">{t("setup.tabRemote")}</Tabs.Tab>
          </Tabs.List>
          <Tabs.Panel value="desktop" pt="md">
            <DesktopSetup />
          </Tabs.Panel>
          <Tabs.Panel value="remote" pt="md">
            <RemoteSetup />
          </Tabs.Panel>
        </Tabs>
      </Stack>
    </Card>
  );
}

function DesktopSetup() {
  const { t } = useTranslation("ai");
  const origin = window.location.origin;
  // Ścieżki Windows w JSON-ie: JSON.stringify podwaja ukośniki wsteczne.
  const config = JSON.stringify(
    {
      mcpServers: {
        vardr: {
          command: "C:\\Vardr\\vardr-mcp.exe",
          env: { VARDR_URL: origin, VARDR_TOKEN_FILE: "C:\\Vardr\\token.txt", VARDR_CA_FILE: "C:\\Vardr\\vardr-ca.crt" },
        },
      },
    },
    null,
    2,
  );
  return (
    <Stack>
      <List type="ordered" size="sm" spacing="sm">
        <List.Item>
          {t("setup.step1")}{" "}
          <Anchor component={Link} to="/admin/api-tokens">
            {t("setup.tokens")}
          </Anchor>
        </List.Item>
        <List.Item>
          {t("setup.step2")}
          <Group gap="xs" mt={4}>
            <Button component="a" href="/api/v1/ai/vardr-mcp.exe" size="xs" variant="light" leftSection={<IconDownload size={14} />}>
              vardr-mcp.exe
            </Button>
            <Button component="a" href="/api/v1/ai/ca.crt" size="xs" variant="light" leftSection={<IconDownload size={14} />}>
              vardr-ca.crt
            </Button>
          </Group>
        </List.Item>
        <List.Item>
          {t("setup.step3")}
          <Stack gap={4} mt={4}>
            <Group gap="xs">
              <Text size="sm">{t("setup.address")}</Text>
              <CopyLine value={origin} />
            </Group>
            <Text size="xs" c="dimmed">
              {t("setup.wizard")}
            </Text>
          </Stack>
        </List.Item>
        <List.Item>{t("setup.step4")}</List.Item>
      </List>
      <Alert variant="light" color="gray" title={t("setup.defenderTitle")}>
        <Text size="sm">{t("setup.defender")}</Text>
      </Alert>
      <Accordion variant="contained">
        <Accordion.Item value="manual">
          <Accordion.Control>{t("setup.manualTitle")}</Accordion.Control>
          <Accordion.Panel>
            <Stack>
              <Text size="sm">{t("setup.manual")}</Text>
              <CopyBlock value={config} />
              <Text size="sm">{t("setup.check")}</Text>
              <Code block>C:\Vardr\vardr-mcp.exe check</Code>
              <Text size="xs" c="dimmed">
                {t("setup.local")}
              </Text>
            </Stack>
          </Accordion.Panel>
        </Accordion.Item>
      </Accordion>
    </Stack>
  );
}

// RemoteSetup: panel jako serwer MCP (Streamable HTTP) – klient AI na
// serwerze albo w sieci (np. własny LLM z Open WebUI), bez vardr-mcp.
function RemoteSetup() {
  const { t } = useTranslation("ai");
  const endpoint = `${window.location.origin}/api/v1/mcp`;
  const example = JSON.stringify(
    { mcpServers: { vardr: { type: "http", url: endpoint, headers: { Authorization: "Bearer vardr_…" } } } },
    null,
    2,
  );
  const test = `curl --cacert vardr-ca.crt -H "Authorization: Bearer $VARDR_TOKEN" -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' ${endpoint}`;
  return (
    <Stack>
      <Text size="sm">{t("setup.remote.intro")}</Text>
      <List type="ordered" size="sm" spacing="sm">
        <List.Item>
          {t("setup.remote.step1")}{" "}
          <Anchor component={Link} to="/admin/api-tokens">
            {t("setup.tokens")}
          </Anchor>
        </List.Item>
        <List.Item>
          {t("setup.remote.step2")}
          <Stack gap={4} mt={4}>
            <Group gap="xs">
              <Text size="sm">{t("setup.remote.url")}</Text>
              <CopyLine value={endpoint} />
            </Group>
            <Group gap="xs">
              <Text size="sm">{t("setup.remote.header")}</Text>
              <CopyLine value="Authorization: Bearer vardr_…" />
            </Group>
          </Stack>
        </List.Item>
        <List.Item>
          {t("setup.remote.step3")}
          <Group gap="xs" mt={4}>
            <Button component="a" href="/api/v1/ai/ca.crt" size="xs" variant="light" leftSection={<IconDownload size={14} />}>
              vardr-ca.crt
            </Button>
          </Group>
        </List.Item>
        <List.Item>
          {t("setup.remote.step4")}
          <CopyBlock value={test} />
        </List.Item>
      </List>
      <Text size="sm">{t("setup.remote.example")}</Text>
      <CopyBlock value={example} />
      <Alert variant="light" color="yellow" icon={<IconAlertTriangle size={16} />} title={t("setup.remote.modelTitle")}>
        <Text size="sm">{t("setup.remote.model")}</Text>
      </Alert>
      <Text size="xs" c="dimmed">
        {t("setup.remote.notes")}
      </Text>
    </Stack>
  );
}

function Reveal() {
  const { t } = useTranslation("ai");
  const [p, setP] = useState("");
  const [reason, setReason] = useState("");
  const [result, setResult] = useState<{ value: string; kind: string } | null>(null);
  const reveal = async () => {
    try {
      const r = await aiApi.reveal(p, reason);
      setResult({ value: r.pseudonym.value, kind: r.pseudonym.kind });
    } catch (e) {
      setResult(null);
      notifications.show({ color: "red", message: errMsg(e) });
    }
  };
  return (
    <Card withBorder>
      <Stack>
        <Title order={4}>{t("reveal.title")}</Title>
        <Text size="sm" c="dimmed">
          {t("reveal.help")}
        </Text>
        <Group align="flex-end">
          <TextInput label={t("reveal.pseudonym")} placeholder="USER-7F3A12BC" value={p} onChange={(e) => setP(e.currentTarget.value)} />
          <TextInput
            label={t("reveal.reason")}
            placeholder={t("reveal.reasonPlaceholder")}
            style={{ flex: 1 }}
            value={reason}
            onChange={(e) => setReason(e.currentTarget.value)}
          />
          <Button leftSection={<IconEye size={16} />} disabled={!p.trim() || reason.trim().length < 3} onClick={() => void reveal()}>
            {t("reveal.button")}
          </Button>
        </Group>
        {result && (
          <Alert color="blue">
            {t("reveal.result", { kind: result.kind })} <Code>{result.value}</Code>
          </Alert>
        )}
      </Stack>
    </Card>
  );
}

function History({ refresh }: { refresh: number }) {
  const { t } = useTranslation("ai");
  const [rows, setRows] = useState<AIRequest[]>([]);
  const [more, setMore] = useState(false);
  const load = useCallback((before?: number) => {
    aiApi
      .requests(before)
      .then((r) => {
        setRows((prev) => (before ? [...prev, ...r.requests] : r.requests));
        setMore(r.requests.length === 100);
      })
      .catch(() => setRows([]));
  }, []);
  useEffect(() => load(), [load, refresh]);
  return (
    <Card withBorder>
      <Stack>
        <Title order={4}>{t("history.title")}</Title>
        <Table.ScrollContainer minWidth={700}>
          <Table striped verticalSpacing={4} fz="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("history.time")}</Table.Th>
                <Table.Th>{t("history.token")}</Table.Th>
                <Table.Th>{t("history.request")}</Table.Th>
                <Table.Th>{t("history.status")}</Table.Th>
                <Table.Th>{t("history.duration")}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {rows.length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={5}>
                    <Text size="sm" c="dimmed">
                      {t("history.empty")}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              )}
              {rows.map((r) => (
                <Table.Tr key={r.id}>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(r.at)}</Table.Td>
                  <Table.Td>{r.token_name}</Table.Td>
                  <Table.Td>
                    <Code style={{ wordBreak: "break-all" }}>
                      {r.method} {r.path}
                    </Code>
                  </Table.Td>
                  <Table.Td>
                    <Badge color={r.status >= 400 ? "orange" : "green"} variant="light">
                      {r.status}
                    </Badge>
                  </Table.Td>
                  <Table.Td>{formatNumber(r.duration_ms)} ms</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
        {more && (
          <Button variant="default" onClick={() => load(rows[rows.length - 1]?.id)}>
            {t("history.older")}
          </Button>
        )}
      </Stack>
    </Card>
  );
}

// Dostęp AI (MCP): ostrzeżenia, polityka, podłączenie, pseudonimy, historia.
export default function AiAccessPage() {
  const { t } = useTranslation("ai");
  const { can } = useAuth();
  const [refresh, setRefresh] = useState(0);
  return (
    <Stack>
      <div>
        <Title order={2}>{t("title")}</Title>
        <Text c="dimmed" size="sm" maw={900}>
          {t("intro")}
        </Text>
      </div>
      <AIWarnings />
      <Policy onSaved={() => setRefresh((n) => n + 1)} />
      <Setup />
      {can("ai", "reveal") && <Reveal />}
      <History refresh={refresh} />
    </Stack>
  );
}
