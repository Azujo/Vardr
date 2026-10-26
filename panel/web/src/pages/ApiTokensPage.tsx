// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import {
  ActionIcon,
  Alert,
  Anchor,
  Badge,
  Button,
  Code,
  CopyButton,
  Group,
  Modal,
  NumberInput,
  SegmentedControl,
  Checkbox,
  PasswordInput,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCheck, IconCopy, IconHistory, IconKey, IconPlus, IconTrash } from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import { api, formatDate, formatNumber, profileName, type APIRequest, type APIToken, type APITokenKind, type Profile } from "../api";
import { AIWarnings } from "./AiAccessPage";
import { useAuth } from "../auth";

function errorMessage(err: unknown) {
  return err instanceof Error ? err.message : String(err);
}

const DAY = 24 * 3600 * 1000;

// Stan tokenu: unieważniony, wygasły, wkrótce wygasa (14 dni) albo aktywny.
function tokenState(tk: APIToken): "revoked" | "expired" | "expiring" | "active" {
  if (tk.revoked_at) return "revoked";
  const left = new Date(tk.expires_at).getTime() - Date.now();
  if (left <= 0) return "expired";
  return left < 14 * DAY ? "expiring" : "active";
}

const stateColors = { revoked: "gray", expired: "gray", expiring: "orange", active: "green" };

// Token pokazywany jeden raz – z przykładem użycia.
function NewSecret({ data, onClose }: { data: { token: APIToken; secret: string } | null; onClose: () => void }) {
  const { t } = useTranslation("admin");
  const ai = data?.token.kind === "ai";
  const example = !data
    ? ""
    : ai
      ? `VARDR_URL=${window.location.origin}\nVARDR_TOKEN=${data.secret}`
      : `curl -H "Authorization: Bearer ${data.secret}" ${window.location.origin}/api/v1/alerts?status=open`;
  return (
    <Modal opened={data !== null} onClose={onClose} title={t("tokens.secretTitle", { name: data?.token.name ?? "" })} centered size="lg">
      {data && (
        <Stack>
          <Text size="sm">
            {t("tokens.secretText")} <b>{t("tokens.secretOnce")}</b>
          </Text>
          <Group wrap="nowrap" align="flex-start">
            <Code block style={{ flex: 1, wordBreak: "break-all", whiteSpace: "pre-wrap" }}>
              {data.secret}
            </Code>
            <CopyButton value={data.secret}>
              {({ copied, copy }) => (
                <Button leftSection={copied ? <IconCheck size={16} /> : <IconCopy size={16} />} onClick={copy}>
                  {copied ? t("copied") : t("copy")}
                </Button>
              )}
            </CopyButton>
          </Group>
          <Text size="sm" fw={500}>
            {ai ? t("tokens.exampleAi") : t("tokens.example")}
          </Text>
          <Code block style={{ wordBreak: "break-all", whiteSpace: "pre-wrap" }}>
            {example}
          </Code>
          <Button variant="default" onClick={onClose}>
            {t("done")}
          </Button>
        </Stack>
      )}
    </Modal>
  );
}

function statusColor(status: number) {
  if (status >= 500) return "red";
  if (status >= 400) return "orange";
  return "green";
}

// Historia zapytań tokenu: najnowsze pierwsze, doładowywanie starszych.
function RequestHistory({ token, days, onClose }: { token: APIToken | null; days: number; onClose: () => void }) {
  const { t } = useTranslation("admin");
  const [rows, setRows] = useState<APIRequest[]>([]);
  const [more, setMore] = useState(false);
  const [error, setError] = useState("");
  const load = useCallback(
    (before?: number) => {
      if (!token) return;
      api
        .apiTokenRequests(token.id, before)
        .then((r) => {
          setRows((prev) => (before ? [...prev, ...r.requests] : r.requests));
          setMore(r.requests.length === 100);
        })
        .catch((e) => setError(errorMessage(e)));
    },
    [token],
  );
  useEffect(() => {
    setRows([]);
    setError("");
    load();
  }, [load]);
  return (
    <Modal opened={token !== null} onClose={onClose} title={t("tokens.historyTitle", { name: token?.name ?? "" })} centered size="xl">
      <Stack>
        <Text size="sm" c="dimmed">
          {t("tokens.historyIntro", { days })}
        </Text>
        {error && <Alert color="red">{error}</Alert>}
        <Table.ScrollContainer minWidth={640}>
          <Table striped verticalSpacing={4} fz="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("tokens.req.time")}</Table.Th>
                <Table.Th>{t("tokens.req.request")}</Table.Th>
                <Table.Th>{t("tokens.req.status")}</Table.Th>
                <Table.Th>{t("tokens.req.duration")}</Table.Th>
                <Table.Th>{t("tokens.req.ip")}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {rows.length === 0 && !error && (
                <Table.Tr>
                  <Table.Td colSpan={5}>
                    <Text c="dimmed" size="sm">
                      {t("tokens.noRequests")}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              )}
              {rows.map((r) => (
                <Table.Tr key={r.id}>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(r.at)}</Table.Td>
                  <Table.Td>
                    <Code style={{ wordBreak: "break-all" }}>
                      {r.method} {r.path}
                    </Code>
                  </Table.Td>
                  <Table.Td>
                    <Badge color={statusColor(r.status)} variant="light">
                      {r.status}
                    </Badge>
                  </Table.Td>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>{formatNumber(r.duration_ms)} ms</Table.Td>
                  <Table.Td>{r.ip}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
        {more && (
          <Button variant="default" onClick={() => load(rows[rows.length - 1]?.id)}>
            {t("tokens.older")}
          </Button>
        )}
      </Stack>
    </Modal>
  );
}

export default function ApiTokensPage() {
  const { t } = useTranslation("admin");
  const { can } = useAuth();
  const canWrite = can("users", "write");
  const [tokens, setTokens] = useState<APIToken[]>([]);
  const [enabled, setEnabled] = useState(true);
  const [limits, setLimits] = useState({ def: 90, max: 365 });
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [logDays, setLogDays] = useState(30);
  const [history, setHistory] = useState<APIToken | null>(null);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [error, setError] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const emptyForm = { name: "", description: "", profile: "viewer", days: 90, kind: "integration" as APITokenKind };
  const [form, setForm] = useState(emptyForm);
  const [ack, setAck] = useState(false);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [secret, setSecret] = useState<{ token: APIToken; secret: string } | null>(null);
  const [revoke, setRevoke] = useState<APIToken | null>(null);

  const load = useCallback(() => {
    api
      .apiTokens()
      .then((r) => {
        setTokens(r.tokens);
        setEnabled(r.enabled);
        if (r.default_days && r.max_days) setLimits({ def: r.default_days, max: r.max_days });
        setCounts(r.requests_24h ?? {});
        if (r.log_days) setLogDays(r.log_days);
      })
      .catch((e) => setError(errorMessage(e)));
    api
      .profiles()
      .then((r) => setProfiles(r.profiles))
      .catch(() => setProfiles([]));
  }, []);
  useEffect(load, [load]);

  const profileOptions = profiles.map((p) => ({ value: p.id, label: profileName(p.id, p.name) }));
  const profileLabel = (id: string) => {
    const p = profiles.find((x) => x.id === id);
    return p ? profileName(p.id, p.name) : id;
  };
  const isAdmin = profiles.find((p) => p.id === form.profile)?.admin ?? form.profile === "admin";

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await api.createAPIToken({ ...form, password, acknowledge: form.kind === "ai" && ack });
      setCreateOpen(false);
      setForm({ ...emptyForm, days: limits.def });
      setAck(false);
      setPassword("");
      setSecret(res);
      load();
    } catch (err) {
      notifications.show({ color: "red", message: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  const doRevoke = async () => {
    if (!revoke) return;
    setBusy(true);
    try {
      await api.revokeAPIToken(revoke.id);
      notifications.show({ color: "green", message: t("tokens.revoked", { name: revoke.name }) });
      setRevoke(null);
      load();
    } catch (err) {
      notifications.show({ color: "red", message: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack>
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>{t("tokens.title")}</Title>
          <Text c="dimmed" size="sm" maw={820}>
            {t("tokens.intro")}{" "}
            <Anchor href="/api/v1/openapi.json" target="_blank" rel="noopener noreferrer">
              {t("tokens.openapi")}
            </Anchor>
          </Text>
        </div>
        {canWrite && enabled && (
          <Button
            leftSection={<IconPlus size={18} />}
            onClick={() => {
              setPassword("");
              setForm({ ...emptyForm, days: limits.def });
              setAck(false);
              setCreateOpen(true);
            }}
          >
            {t("tokens.new")}
          </Button>
        )}
      </Group>
      {error && <Alert color="red">{error}</Alert>}
      {!enabled && <Alert color="gray">{t("tokens.disabled")}</Alert>}

      <Table.ScrollContainer minWidth={820}>
        <Table striped highlightOnHover verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t("tokens.col.name")}</Table.Th>
              <Table.Th>{t("tokens.col.profile")}</Table.Th>
              <Table.Th>{t("tokens.col.token")}</Table.Th>
              <Table.Th>{t("tokens.col.state")}</Table.Th>
              <Table.Th>{t("tokens.col.expires")}</Table.Th>
              <Table.Th>{t("tokens.col.lastUse")}</Table.Th>
              <Table.Th>{t("tokens.col.requests")}</Table.Th>
              <Table.Th>{t("tokens.col.created")}</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {tokens.length === 0 && (
              <Table.Tr>
                <Table.Td colSpan={9}>
                  <Text c="dimmed" size="sm">
                    {t("tokens.empty")}
                  </Text>
                </Table.Td>
              </Table.Tr>
            )}
            {tokens.map((tk) => {
              const st = tokenState(tk);
              return (
                <Table.Tr key={tk.id} style={st === "revoked" || st === "expired" ? { opacity: 0.6 } : undefined}>
                  <Table.Td>
                    <Group gap={6}>
                      <Text fw={500}>{tk.name}</Text>
                      {tk.kind === "ai" && (
                        <Badge size="xs" color="violet" variant="light">
                          AI
                        </Badge>
                      )}
                    </Group>
                    {tk.description && (
                      <Text size="xs" c="dimmed">
                        {tk.description}
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>{profileLabel(tk.profile)}</Table.Td>
                  <Table.Td>
                    <Code>{tk.prefix}…</Code>
                  </Table.Td>
                  <Table.Td>
                    <Tooltip
                      label={tk.revoked_at ? t("tokens.revokedBy", { by: tk.revoked_by, date: formatDate(tk.revoked_at) }) : ""}
                      disabled={!tk.revoked_at}
                    >
                      <Badge color={stateColors[st]} variant="light">
                        {t(`tokens.state.${st}`)}
                      </Badge>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{formatDate(tk.expires_at)}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{tk.last_used_at ? formatDate(tk.last_used_at) : t("tokens.never")}</Text>
                    {tk.last_used_ip && (
                      <Text size="xs" c="dimmed">
                        {tk.last_used_ip}
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    <Tooltip label={t("tokens.history")}>
                      <Button
                        variant="subtle"
                        size="compact-sm"
                        leftSection={<IconHistory size={16} />}
                        aria-label={t("tokens.historyOf", { name: tk.name })}
                        onClick={() => setHistory(tk)}
                      >
                        {formatNumber(counts[String(tk.id)] ?? 0)}
                      </Button>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{formatDate(tk.created_at)}</Text>
                    <Text size="xs" c="dimmed">
                      {tk.created_by}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    {canWrite && !tk.revoked_at && (
                      <Tooltip label={t("tokens.revoke")}>
                        <ActionIcon variant="subtle" color="red" aria-label={t("tokens.revokeOf", { name: tk.name })} onClick={() => setRevoke(tk)}>
                          <IconTrash size={18} />
                        </ActionIcon>
                      </Tooltip>
                    )}
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={createOpen} onClose={() => setCreateOpen(false)} title={t("tokens.new")} centered size="lg">
        <form onSubmit={create}>
          <Stack>
            <SegmentedControl
              value={form.kind}
              onChange={(v) => setForm({ ...form, kind: v as APITokenKind })}
              data={[
                { value: "integration", label: t("tokens.kindIntegration") },
                { value: "ai", label: t("tokens.kindAi") },
              ]}
            />
            {form.kind === "ai" && (
              <>
                <Text size="sm" c="dimmed">
                  {t("tokens.aiHelp")}
                </Text>
                <AIWarnings />
                <Checkbox label={t("tokens.aiAck")} checked={ack} onChange={(e) => setAck(e.currentTarget.checked)} />
              </>
            )}
            <TextInput
              label={t("tokens.col.name")}
              description={t("tokens.nameHint")}
              required
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.currentTarget.value })}
            />
            <TextInput
              label={t("tokens.description")}
              placeholder={t("tokens.descriptionPlaceholder")}
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.currentTarget.value })}
            />
            <Select
              label={t("tokens.col.profile")}
              description={t("tokens.profileHint")}
              data={profileOptions}
              value={form.profile}
              allowDeselect={false}
              onChange={(v) => v && setForm({ ...form, profile: v })}
            />
            {isAdmin && (
              <Alert color="orange" icon={<IconKey size={18} />}>
                {t("tokens.adminWarning")}
              </Alert>
            )}
            <NumberInput
              label={t("tokens.days")}
              min={1}
              max={limits.max}
              value={form.days}
              onChange={(v) => setForm({ ...form, days: typeof v === "number" ? v : limits.def })}
            />
            <PasswordInput label={t("yourPassword")} required value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
            <Button type="submit" loading={busy} disabled={!password || form.name.trim().length < 2 || (form.kind === "ai" && !ack)}>
              {t("tokens.create")}
            </Button>
          </Stack>
        </form>
      </Modal>
      <NewSecret data={secret} onClose={() => setSecret(null)} />
      <RequestHistory token={history} days={logDays} onClose={() => setHistory(null)} />
      <Modal opened={!!revoke} onClose={() => setRevoke(null)} title={t("tokens.revokeTitle", { name: revoke?.name ?? "" })} centered>
        {revoke && (
          <Stack>
            <Text size="sm">{t("tokens.revokeText")}</Text>
            <Button color="red" loading={busy} onClick={() => void doRevoke()}>
              {t("tokens.revoke")}
            </Button>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
