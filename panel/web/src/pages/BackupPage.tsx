// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert as MAlert,
  Badge,
  Button,
  Card,
  Checkbox,
  Code,
  CopyButton,
  Group,
  Modal,
  NumberInput,
  PasswordInput,
  Radio,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  TextInput,
  Textarea,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCopy, IconDeviceFloppy, IconKey, IconPlayerPlay, IconPlugConnected } from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import i18n from "../i18n";
import RestorePanel from "./BackupRestore";
import {
  ApiError,
  backupApi,
  formatBytes,
  formatDate,
  type BackupConfig,
  type BackupMethod,
  type BackupRun,
  type BackupView,
} from "../api";

// Kopie zapasowe: ustawienia dla usługi siem-backup, zlecenia i historia.

// Dni tygodnia 1–7 (poniedziałek–niedziela) w języku użytkownika.
const weekdays = () =>
  [1, 2, 3, 4, 5, 6, 7].map((d) => ({
    value: String(d),
    label: new Date(Date.UTC(2024, 0, d)).toLocaleDateString(i18n.resolvedLanguage ?? "pl", { weekday: "long", timeZone: "UTC" }),
  }));

// Kolory stanów kopii; nazwy – backup: status.<stan>, metody – backup: method.<metoda>.
const runColors: Record<BackupRun["status"], string> = { running: "blue", ok: "green", partial: "orange", error: "red" };
const methods: BackupMethod[] = ["none", "sftp", "smb", "s3"];

function err(e: unknown) {
  notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
}

function pad(n: number) {
  return String(n).padStart(2, "0");
}

function scheduleText(c: BackupConfig): string {
  const s = c.schedule;
  const at = `${pad(s.hour)}:${pad(s.minute)}`;
  if (!c.enabled) return i18n.t("backup:schedule.off");
  if (s.kind === "hours") return i18n.t("backup:schedule.hours", { n: s.every_hours, m: pad(s.minute) });
  if (s.kind === "weekly") return i18n.t("backup:schedule.weekly", { day: weekdays()[(s.weekday ?? 1) - 1]?.label, at });
  return i18n.t("backup:schedule.daily", { at });
}

export default function BackupPage() {
  const { t: tr } = useTranslation("backup");
  const [view, setView] = useState<BackupView | null>(null);
  const [cfg, setCfg] = useState<BackupConfig | null>(null);
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [confirm, setConfirm] = useState(false);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState("settings");

  const load = useCallback(async (resetForm: boolean) => {
    try {
      const v = await backupApi.get();
      setView(v);
      if (resetForm) {
        setCfg(structuredClone(v.state.config));
        setSecrets({});
      }
    } catch (e) {
      err(e);
    }
  }, []);
  useEffect(() => void load(true), [load]);

  const pending = !!view?.state.requests.some((r) => !r.done_at) || !!view?.state.runs.some((r) => r.status === "running");
  useEffect(() => {
    const t = setInterval(() => void load(false), pending ? 4000 : 30000);
    return () => clearInterval(t);
  }, [load, pending]);

  // Wynik zlecenia z panelu – powiadomienie, gdy się zakończy.
  const [watching, setWatching] = useState<number[]>([]);
  useEffect(() => {
    if (!view) return;
    for (const id of watching) {
      const r = view.state.requests.find((x) => x.id === id);
      if (r?.done_at) {
        notifications.show({ color: r.ok ? "green" : "red", autoClose: r.ok ? 8000 : false, message: r.message || (r.ok ? tr("done") : tr("failed")) });
        setWatching((w) => w.filter((x) => x !== id));
      }
    }
  }, [view, watching]);

  const dirty = useMemo(
    () => !!view && !!cfg && (JSON.stringify(cfg) !== JSON.stringify(view.state.config) || Object.values(secrets).some((v) => v.trim() !== "")),
    [view, cfg, secrets],
  );

  if (!view || !cfg) return <Text c="dimmed">{tr("loading")}</Text>;
  const st = view.state;
  const runner = st.runner;
  const t = cfg.target;
  const set = (f: (c: BackupConfig) => void) =>
    setCfg((c) => {
      const n = structuredClone(c!);
      f(n);
      return n;
    });
  const secretSet = (name: string) => st.secrets.some((s) => s.name === name) && !view.stale_secrets.includes(name);
  const secretHint = (name: string) =>
    view.stale_secrets.includes(name)
      ? tr("secret.stale")
      : secretSet(name)
        ? tr("secret.saved")
        : "";

  const ask = async (action: "run" | "test" | "genkey" | "list" | "inspect", file?: { location: string; name: string }) => {
    try {
      const r = await backupApi.request(action, file);
      setWatching((w) => [...w, r.request.id]);
      notifications.show({ message: tr("requested") });
      void load(false);
    } catch (e) {
      err(e);
    }
  };

  const save = async () => {
    setBusy(true);
    try {
      await backupApi.save(cfg, secrets, password);
      notifications.show({ color: "green", message: tr("saved") });
      setConfirm(false);
      setPassword("");
      await load(true);
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) setPassword("");
      err(e);
    } finally {
      setBusy(false);
    }
  };

  const restoring = st.requests.some((r) => r.action === "restore" && !r.done_at);
  const last = st.runs.find((r) => r.status !== "running");
  const lastOK = st.runs.find((r) => r.status === "ok" || r.status === "partial");

  return (
    <Stack>
      <div>
        <Title order={2}>{tr("title")}</Title>
        <Text c="dimmed" size="sm">
          {tr("intro")}
        </Text>
      </div>

      {!view.online && (
        <MAlert color="red" title={tr("offline.title")}>
          {runner?.seen_at ? tr("offline.lastSeen", { date: formatDate(runner.seen_at) }) : tr("offline.never")}
        </MAlert>
      )}
      {runner && !runner.pass_id && (
        <MAlert color="red" title={tr("noPass.title")}>
          {tr("noPass.text.0")}
          <Code>{tr("noPass.cmd")}</Code>
          {tr("noPass.text.1")}
        </MAlert>
      )}

      <SimpleGrid cols={{ base: 1, md: 3 }}>
        <Card withBorder>
          <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
            {tr("last")}
          </Text>
          {last ? (
            <>
              <Group gap="xs" mt={4}>
                <Badge color={runColors[last.status]}>{tr(`status.${last.status}`)}</Badge>
                <Text size="sm">{formatDate(last.started_at)}</Text>
              </Group>
              {lastOK && lastOK.id !== last.id && (
                <Text size="xs" c="dimmed" mt={4}>
                  {tr("lastOk", { date: formatDate(lastOK.started_at) })}
                </Text>
              )}
            </>
          ) : (
            <Text size="sm" mt={4}>
              {tr("none")}
            </Text>
          )}
          <Text size="xs" c="dimmed" mt={4}>
            {tr("scheduleIs", { s: scheduleText(st.config) })}
          </Text>
        </Card>
        <Card withBorder>
          <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
            {tr("service")}
          </Text>
          <Group gap="xs" mt={4}>
            <Badge color={view.online ? "green" : "red"}>{view.online ? tr("running") : tr("notResponding")}</Badge>
            {runner?.version && <Text size="xs" c="dimmed">{runner.version}</Text>}
          </Group>
          <Tooltip
            multiline
            w={320}
            label={tr("passIdTip")}
          >
            <Text size="xs" c="dimmed" mt={4} style={{ cursor: "help" }}>
              {tr("passId")} {runner?.pass_id ? <Code>{runner.pass_id}</Code> : tr("noPassShort")}
            </Text>
          </Tooltip>
          {runner?.local_dir && (
            <Text size="xs" c="dimmed">
              {tr("local", { dir: runner.local_dir, free: formatBytes(runner.local_free) })}
            </Text>
          )}
        </Card>
        <Card withBorder>
          <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
            {tr("actions")}
          </Text>
          <Stack gap={6} mt={6}>
            <Button size="xs" leftSection={<IconPlayerPlay size={14} />} disabled={!view.online} onClick={() => void ask("run")}>
              {tr("runNow")}
            </Button>
            <Tooltip label={dirty ? tr("saveFirst") : tr("testTip")}>
              <Button
                size="xs"
                variant="light"
                leftSection={<IconPlugConnected size={14} />}
                disabled={!view.online || dirty || st.config.target.method === "none"}
                onClick={() => void ask("test")}
              >
                {tr("test")}
              </Button>
            </Tooltip>
          </Stack>
        </Card>
      </SimpleGrid>

      <Tabs value={tab} onChange={(v) => setTab(v ?? "settings")}>
        <Tabs.List>
          <Tabs.Tab value="settings">{tr("tab.settings")}</Tabs.Tab>
          <Tabs.Tab value="history">{tr("tab.history", { n: st.runs.length })}</Tabs.Tab>
          <Tabs.Tab value="restore" color="red">
            {tr("tab.restore")} {restoring && <Badge size="xs" color="red">{tr("status.running")}</Badge>}
          </Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="settings" pt="md">
          <Stack>
          <Card withBorder>
            <Group justify="space-between" mb="xs">
              <Title order={4}>{tr("schedule.title")}</Title>
              <Switch label={tr("schedule.enabled")} checked={cfg.enabled} onChange={(e) => set((c) => (c.enabled = e.currentTarget.checked))} />
            </Group>
            <Group align="flex-end">
              <SegmentedControl
                value={cfg.schedule.kind}
                onChange={(v) =>
                  set((c) => {
                    c.schedule.kind = v as BackupConfig["schedule"]["kind"];
                    if (v === "hours" && !c.schedule.every_hours) c.schedule.every_hours = 6;
                    if (v === "weekly" && !c.schedule.weekday) c.schedule.weekday = 7;
                  })
                }
                data={[
                  { value: "hours", label: tr("schedule.kind.hours") },
                  { value: "daily", label: tr("schedule.kind.daily") },
                  { value: "weekly", label: tr("schedule.kind.weekly") },
                ]}
              />
              {cfg.schedule.kind === "hours" && (
                <Select
                  label={tr("schedule.everyHours")}
                  w={140}
                  allowDeselect={false}
                  value={String(cfg.schedule.every_hours ?? 6)}
                  onChange={(v) => set((c) => (c.schedule.every_hours = Number(v)))}
                  data={["1", "2", "3", "4", "6", "8", "12"]}
                />
              )}
              {cfg.schedule.kind === "weekly" && (
                <Select
                  label={tr("schedule.day")}
                  w={160}
                  allowDeselect={false}
                  value={String(cfg.schedule.weekday ?? 7)}
                  onChange={(v) => set((c) => (c.schedule.weekday = Number(v)))}
                  data={weekdays()}
                />
              )}
              {cfg.schedule.kind !== "hours" && (
                <NumberInput label={tr("schedule.hour")} w={100} min={0} max={23} value={cfg.schedule.hour} onChange={(v) => set((c) => (c.schedule.hour = Number(v) || 0))} />
              )}
              <NumberInput label={tr("schedule.minute")} w={100} min={0} max={59} value={cfg.schedule.minute} onChange={(v) => set((c) => (c.schedule.minute = Number(v) || 0))} />
            </Group>
            <Text size="xs" c="dimmed" mt="xs">
              {tr("schedule.hint")}
            </Text>
          </Card>

          <Card withBorder>
            <Title order={4} mb="xs">
              {tr("include.title")}
            </Title>
            <Stack gap="xs">
              <Checkbox
                label={tr("include.saga")}
                description={tr("include.sagaHint")}
                checked={cfg.include.saga}
                onChange={(e) => set((c) => (c.include.saga = e.currentTarget.checked))}
              />
              <Checkbox
                label={tr("include.config")}
                description={tr("include.configHint")}
                checked={cfg.include.config}
                onChange={(e) => set((c) => (c.include.config = e.currentTarget.checked))}
              />
              <Checkbox
                label={tr("include.archive")}
                description={tr("include.archiveHint")}
                checked={cfg.include.archive}
                onChange={(e) => set((c) => (c.include.archive = e.currentTarget.checked))}
              />
              <Checkbox
                label={tr("include.grafana")}
                description={tr("include.grafanaHint")}
                checked={cfg.include.grafana}
                onChange={(e) => set((c) => (c.include.grafana = e.currentTarget.checked))}
              />
              {(!cfg.include.saga || !cfg.include.config) && (
                <MAlert color="orange">
                  {tr("include.warning")}
                </MAlert>
              )}
              <Text size="xs" c="dimmed">
                {tr("include.events")}
              </Text>
            </Stack>
          </Card>

          <Card withBorder>
            <Title order={4} mb="xs">
              {tr("retention.title")}
            </Title>
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <Stack gap={4}>
                <Text size="sm" fw={500}>
                  {tr("retention.local")}
                </Text>
                <Group>
                  <NumberInput label={tr("retention.days")} w={120} min={1} max={3650} value={cfg.local.keep_days} onChange={(v) => set((c) => (c.local.keep_days = Number(v) || 1))} />
                  <NumberInput
                    label={tr("retention.count")}
                    description={tr("retention.unlimited")}
                    w={140}
                    min={0}
                    max={1000}
                    value={cfg.local.keep_count}
                    onChange={(v) => set((c) => (c.local.keep_count = Number(v) || 0))}
                  />
                </Group>
              </Stack>
              <Stack gap={4}>
                <Text size="sm" fw={500} c={t.method === "none" ? "dimmed" : undefined}>
                  {tr("retention.remote")}
                </Text>
                <Group>
                  <NumberInput
                    label={tr("retention.days")}
                    w={120}
                    min={1}
                    max={3650}
                    disabled={t.method === "none"}
                    value={cfg.remote.keep_days}
                    onChange={(v) => set((c) => (c.remote.keep_days = Number(v) || 1))}
                  />
                  <NumberInput
                    label={tr("retention.count")}
                    description={tr("retention.unlimited")}
                    w={140}
                    min={0}
                    max={1000}
                    disabled={t.method === "none"}
                    value={cfg.remote.keep_count}
                    onChange={(v) => set((c) => (c.remote.keep_count = Number(v) || 0))}
                  />
                </Group>
              </Stack>
            </SimpleGrid>
            <Text size="xs" c="dimmed" mt="xs">
              {tr("retention.hint")}
            </Text>
          </Card>

          <Card withBorder>
            <Title order={4} mb="xs">
              {tr("target.title")}
            </Title>
            <Stack gap="sm">
              <Select
                w={320}
                allowDeselect={false}
                value={t.method}
                onChange={(v) =>
                  set((c) => {
                    c.target = { method: v as BackupMethod, auth: v === "sftp" ? "server_key" : undefined };
                  })
                }
                data={methods.map((m) => ({ value: m, label: tr(`method.${m}`) }))}
              />
              {t.method === "none" && (
                <MAlert color="orange">
                  {tr("target.localOnly")}
                </MAlert>
              )}
              {(t.method === "sftp" || t.method === "smb") && (
                <Group align="flex-end">
                  <TextInput label={tr("target.host")} placeholder="192.168.88.180" w={220} value={t.host ?? ""} onChange={(e) => set((c) => (c.target.host = e.currentTarget.value))} />
                  <NumberInput
                    label="Port"
                    placeholder={t.method === "sftp" ? "22" : "445"}
                    w={100}
                    min={1}
                    max={65535}
                    value={t.port || ""}
                    onChange={(v) => set((c) => (c.target.port = Number(v) || undefined))}
                  />
                  <TextInput label={tr("target.user")} w={180} value={t.user ?? ""} onChange={(e) => set((c) => (c.target.user = e.currentTarget.value))} />
                  {t.method === "smb" && (
                    <>
                      <TextInput label={tr("target.share")} placeholder={tr("target.sharePlaceholder")} w={160} value={t.share ?? ""} onChange={(e) => set((c) => (c.target.share = e.currentTarget.value))} />
                      <TextInput label={tr("target.domain")} w={160} value={t.domain ?? ""} onChange={(e) => set((c) => (c.target.domain = e.currentTarget.value))} />
                    </>
                  )}
                </Group>
              )}
              {t.method === "s3" && (
                <Group align="flex-end">
                  <TextInput
                    label={tr("target.endpoint")}
                    description={tr("target.endpointHint")}
                    placeholder="https://minio.firma.local:9000"
                    w={300}
                    value={t.endpoint ?? ""}
                    onChange={(e) => set((c) => (c.target.endpoint = e.currentTarget.value))}
                  />
                  <TextInput label="Region" placeholder="eu-central-1" w={150} value={t.region ?? ""} onChange={(e) => set((c) => (c.target.region = e.currentTarget.value))} />
                  <TextInput label={tr("target.bucket")} w={200} value={t.bucket ?? ""} onChange={(e) => set((c) => (c.target.bucket = e.currentTarget.value))} />
                  <TextInput label={tr("target.accessKey")} w={220} value={t.access_key ?? ""} onChange={(e) => set((c) => (c.target.access_key = e.currentTarget.value))} />
                </Group>
              )}
              {t.method !== "none" && (
                <TextInput
                  label={tr("target.path")}
                  description={tr(`target.pathHint.${t.method}`)}
                  placeholder={t.method === "sftp" ? "/mnt/tank/vardr_backup" : "vardr"}
                  maw={520}
                  value={t.path ?? ""}
                  onChange={(e) => set((c) => (c.target.path = e.currentTarget.value))}
                />
              )}

              {t.method === "sftp" && (
                <Radio.Group label={tr("target.auth")} value={t.auth ?? "server_key"} onChange={(v) => set((c) => (c.target.auth = v as typeof t.auth))}>
                  <Stack gap={6} mt={4}>
                    <Radio value="server_key" label={tr("target.authServerKey")} />
                    <Radio value="private_key" label={tr("target.authPrivateKey")} />
                    <Radio value="password" label={tr("target.authPassword")} />
                  </Stack>
                </Radio.Group>
              )}
              {t.method === "sftp" && t.auth === "server_key" && (
                <Stack gap={4}>
                  {runner?.ssh_public_key ? (
                    <>
                      <Text size="sm">
                        {tr("target.addKey.0")}
                        <Code>~/.ssh/authorized_keys</Code>
                        {tr("target.addKey.1")}
                      </Text>
                      <Group gap="xs" wrap="nowrap" align="flex-start">
                        <Code block style={{ wordBreak: "break-all", flex: 1 }}>
                          {runner.ssh_public_key}
                        </Code>
                        <CopyButton value={runner.ssh_public_key}>
                          {({ copied, copy }) => (
                            <Button size="xs" variant="light" leftSection={<IconCopy size={14} />} onClick={copy}>
                              {copied ? tr("copied") : tr("copy")}
                            </Button>
                          )}
                        </CopyButton>
                      </Group>
                    </>
                  ) : (
                    <Text size="sm" c="orange">
                      {tr("target.noKey")}
                    </Text>
                  )}
                  <Group>
                    <Button
                      size="xs"
                      variant="default"
                      leftSection={<IconKey size={14} />}
                      disabled={!view.online}
                      onClick={() => {
                        if (!runner?.ssh_public_key || window.confirm(tr("target.newKeyConfirm"))) void ask("genkey");
                      }}
                    >
                      {runner?.ssh_public_key ? tr("target.newKey") : tr("target.genKey")}
                    </Button>
                  </Group>
                </Stack>
              )}
              {t.method === "sftp" && t.auth === "private_key" && (
                <Textarea
                  label={tr("target.privateKey")}
                  description={secretHint("private_key") || tr("target.privateKeyHint")}
                  placeholder={secretSet("private_key") ? "••••••••" : "-----BEGIN OPENSSH PRIVATE KEY-----"}
                  autosize
                  minRows={3}
                  maxRows={10}
                  spellCheck={false}
                  styles={{ input: { fontFamily: "monospace", fontSize: 11 } }}
                  value={secrets.private_key ?? ""}
                  onChange={(e) => setSecrets((s) => ({ ...s, private_key: e.currentTarget.value }))}
                />
              )}
              {((t.method === "sftp" && t.auth === "password") || t.method === "smb") && (
                <PasswordInput
                  label={tr("target.authPassword")}
                  description={secretHint("password")}
                  placeholder={secretSet("password") ? "••••••••" : ""}
                  w={320}
                  autoComplete="new-password"
                  value={secrets.password ?? ""}
                  onChange={(e) => setSecrets((s) => ({ ...s, password: e.currentTarget.value }))}
                />
              )}
              {t.method === "s3" && (
                <PasswordInput
                  label={tr("target.secretKey")}
                  description={secretHint("s3_secret")}
                  placeholder={secretSet("s3_secret") ? "••••••••" : ""}
                  w={360}
                  autoComplete="new-password"
                  value={secrets.s3_secret ?? ""}
                  onChange={(e) => setSecrets((s) => ({ ...s, s3_secret: e.currentTarget.value }))}
                />
              )}
              {t.method === "sftp" && runner?.host_key && (
                <Text size="xs" c="dimmed">
                  {tr("target.hostKey.0")}
                  <Code>{runner.host_key}</Code>
                  {tr("target.hostKey.1")}
                </Text>
              )}
            </Stack>
          </Card>

          <Group>
            <Button leftSection={<IconDeviceFloppy size={16} />} disabled={!dirty} onClick={() => setConfirm(true)}>
              {tr("saveSettings")}
            </Button>
            {dirty && (
              <Button variant="subtle" onClick={() => void load(true)}>
                {tr("undo")}
              </Button>
            )}
            {st.updated_at && (
              <Text size="xs" c="dimmed">
                {tr("lastChange", { by: st.updated_by, date: formatDate(st.updated_at) })}
              </Text>
            )}
          </Group>

          </Stack>
        </Tabs.Panel>

        <Tabs.Panel value="history" pt="md">
          <Card withBorder>
            <Title order={4} mb="xs">
              {tr("history.title")}
            </Title>
            {st.runs.length === 0 ? (
              <Text size="sm" c="dimmed">
                {tr("history.none")}
              </Text>
            ) : (
              <Table.ScrollContainer minWidth={800}>
                <Table fz="sm" verticalSpacing={4}>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>{tr("history.col.time")}</Table.Th>
                      <Table.Th>{tr("history.col.kind")}</Table.Th>
                      <Table.Th>{tr("history.col.result")}</Table.Th>
                      <Table.Th>{tr("history.col.size")}</Table.Th>
                      <Table.Th>{tr("history.col.upload")}</Table.Th>
                      <Table.Th>{tr("history.col.details")}</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {st.runs.map((r) => (
                      <Table.Tr key={r.id}>
                        <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(r.started_at)}</Table.Td>
                        <Table.Td>{r.kind === "manual" ? tr("history.manual") : tr("history.scheduled")}</Table.Td>
                        <Table.Td>
                          <Badge size="sm" color={runColors[r.status]}>
                            {tr(`status.${r.status}`)}
                          </Badge>
                        </Table.Td>
                        <Table.Td>{r.size_bytes ? formatBytes(r.size_bytes) : "—"}</Table.Td>
                        <Table.Td>{r.remote === "ok" ? tr("history.yes") : r.remote === "error" ? <Text c="red" size="sm">{tr("history.error")}</Text> : "—"}</Table.Td>
                        <Table.Td>
                          <Text size="xs" style={{ wordBreak: "break-word" }}>
                            {r.message}
                          </Text>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            )}
            <Text size="xs" c="dimmed" mt="xs">
              {tr("history.restoreHint.0")}
              <Code>{tr("history.restoreCmd")}</Code>
              {tr("history.restoreHint.1")}
            </Text>
          </Card>
        </Tabs.Panel>

        <Tabs.Panel value="restore" pt="md">
          <RestorePanel view={view} ask={ask} />
        </Tabs.Panel>
      </Tabs>

      <Modal opened={confirm} onClose={() => setConfirm(false)} title={tr("confirm.title")} centered>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <Stack gap="sm">
            <Text size="sm">{tr("confirm.text")}</Text>
            <PasswordInput
              label={tr("yourPassword")}
              required
              autoFocus
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
            />
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setConfirm(false)}>
                {tr("back")}
              </Button>
              <Button type="submit" loading={busy}>
                {tr("save")}
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Stack>
  );
}
