// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import {
  Checkbox,
  ActionIcon,
  Alert,
  Badge,
  Button,
  Group,
  Menu,
  Modal,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Textarea,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconDots, IconEdit, IconPlus, IconTrash } from "@tabler/icons-react";
import { groupsApi, type AgentGroup, type AgentLimits, type AgentProfile } from "../api";
import { useTranslation } from "react-i18next";
import i18n from "../i18n";
import { useAuth } from "../auth";
import { ReauthPassword } from "../sso";

// Nazwy profili i priorytetów tłumaczone przy odczycie (agents: profile.*, priority.*).
export const profileLabels = Object.defineProperties({} as Record<AgentProfile, string>, {
  workstation: { enumerable: true, get: () => i18n.t("agents:profile.workstation") },
  server: { enumerable: true, get: () => i18n.t("agents:profile.server") },
  dc: { enumerable: true, get: () => i18n.t("agents:profile.dc") },
});

const priorities = ["normal", "below_normal", "background"];

function msg(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

// Opis limitów w jednej linii („—” = wartość z agent.yaml / domyślna agenta).
export function limitsSummary(l: AgentLimits): string {
  const t = (k: string, o?: Record<string, unknown>) => i18n.t(`agents:limits.${k}`, o);
  const parts: string[] = [];
  if (l.cpu_max_percent !== undefined) parts.push(l.cpu_max_percent ? t("cpu", { n: l.cpu_max_percent }) : t("cpuNone"));
  if (l.memory_hard_mb !== undefined) parts.push(l.memory_hard_mb ? t("mem", { n: l.memory_hard_mb }) : t("memNone"));
  if (l.max_eps !== undefined) parts.push(l.max_eps ? t("eps", { n: l.max_eps }) : t("epsNone"));
  if (l.max_send_kbps !== undefined) parts.push(l.max_send_kbps ? t("bw", { n: l.max_send_kbps }) : t("bwNone"));
  if (l.buffer_max_mb !== undefined) parts.push(l.buffer_max_mb ? t("buffer", { n: l.buffer_max_mb }) : t("bufferNone"));
  if (l.require_sysmon) parts.push(t("sysmon"));
  if (l.protection === false) parts.push(t("noProtection"));
  if (l.auto_update) parts.push(t("autoUpdate"));
  if (l.iis_logs) parts.push(t("iis"));
  if (l.heartbeat_alert_min) parts.push(t(l.heartbeat_notify_return ? "heartbeatReturn" : "heartbeat", { n: l.heartbeat_alert_min }));
  if (l.priority) parts.push(t("priority", { p: i18n.t(`agents:priority.${l.priority}`) }));
  return parts.length ? parts.join(" · ") : t("defaults");
}

type Form = { name: string; description: string; profile: AgentProfile; limits: AgentLimits };
const emptyForm: Form = { name: "", description: "", profile: "workstation", limits: {} };

// Pole liczbowe limitu: puste = wartość domyślna agenta (pole pominięte).
function LimitInput({
  label,
  description,
  value,
  onChange,
  max,
  suffix,
}: {
  label: string;
  description: string;
  value: number | undefined;
  onChange: (v: number | undefined) => void;
  max: number;
  suffix: string;
}) {
  return (
    <NumberInput
      label={label}
      description={description}
      placeholder={i18n.t("agents:limits.defaults")}
      min={0}
      max={max}
      suffix={suffix}
      value={value ?? ""}
      onChange={(v) => onChange(v === "" ? undefined : Number(v))}
    />
  );
}

export default function GroupsPage() {
  const { t } = useTranslation("agents");
  const { can } = useAuth();
  const admin = can("agents", "write");
  const [groups, setGroups] = useState<AgentGroup[]>([]);
  const [error, setError] = useState("");
  // wasAuto: grupa miała już włączone aktualizacje (włączenie wymaga hasła).
  const [edit, setEdit] = useState<{ id?: number; form: Form; wasAuto?: boolean } | null>(null);
  const [password, setPassword] = useState("");
  const [agentVersion, setAgentVersion] = useState<string>();
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    groupsApi
      .list()
      .then((r) => {
        setGroups(r.groups);
        setAgentVersion(r.agent_version);
      })
      .catch((e) => setError(msg(e)));
  }, []);
  const needPassword = !!edit?.form.limits.auto_update && !edit.wasAuto;
  useEffect(load, [load]);

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!edit) return;
    setBusy(true);
    try {
      const body = needPassword ? { ...edit.form, password } : edit.form;
      if (edit.id) await groupsApi.update(edit.id, body);
      else await groupsApi.create(body);
      notifications.show({
        color: "green",
        message: t("groups.saved"),
      });
      setEdit(null);
      setPassword("");
      load();
    } catch (err) {
      notifications.show({ color: "red", message: msg(err) });
    } finally {
      setBusy(false);
    }
  };

  const remove = async (g: AgentGroup) => {
    if (!window.confirm(t("groups.removeConfirm", { name: g.name }))) return;
    try {
      await groupsApi.remove(g.id);
      load();
    } catch (err) {
      notifications.show({ color: "red", message: msg(err) });
    }
  };

  const setLimit = (k: keyof AgentLimits, v: AgentLimits[keyof AgentLimits]) =>
    edit && setEdit({ ...edit, form: { ...edit.form, limits: { ...edit.form.limits, [k]: v } } });

  return (
    <Stack>
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>{t("groups.title")}</Title>
          <Text c="dimmed" size="sm">
            {t("groups.intro")}
          </Text>
        </div>
        {admin && (
          <Button
            leftSection={<IconPlus size={18} />}
            onClick={() => {
              setPassword("");
              setEdit({ form: emptyForm });
            }}
          >
            {t("groups.new")}
          </Button>
        )}
      </Group>
      {error && <Alert color="red">{error}</Alert>}

      <Table.ScrollContainer minWidth={760}>
        <Table striped verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr style={{ whiteSpace: "nowrap" }}>
              <Table.Th>{t("col.group")}</Table.Th>
              <Table.Th>{t("groups.profile")}</Table.Th>
              <Table.Th>{t("groups.limits")}</Table.Th>
              <Table.Th>{t("stat.total")}</Table.Th>
              <Table.Th>{t("col.version")}</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {groups.map((g) => (
              <Table.Tr key={g.id}>
                <Table.Td>
                  <Group gap={6} wrap="nowrap">
                    <Text fw={600}>{g.name}</Text>
                    {g.is_default && (
                      <Badge size="xs" variant="light">
                        {t("groups.default")}
                      </Badge>
                    )}
                  </Group>
                  {g.description && (
                    <Text size="xs" c="dimmed">
                      {g.description}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>{profileLabels[g.profile]}</Table.Td>
                <Table.Td>
                  <Text size="sm">{limitsSummary(g.limits)}</Text>
                </Table.Td>
                <Table.Td>{g.agents}</Table.Td>
                <Table.Td>
                  <Text size="xs" ff="monospace" c="dimmed">
                    {g.config_version}
                  </Text>
                </Table.Td>
                <Table.Td>
                  {admin && (
                    <Menu position="bottom-end">
                      <Menu.Target>
                        <ActionIcon variant="subtle" aria-label={t("groups.actions", { name: g.name })}>
                          <IconDots size={18} />
                        </ActionIcon>
                      </Menu.Target>
                      <Menu.Dropdown>
                        <Menu.Item
                          leftSection={<IconEdit size={16} />}
                          onClick={() => {
                            setPassword("");
                            setEdit({
                              id: g.id,
                              form: { name: g.name, description: g.description, profile: g.profile, limits: g.limits },
                              wasAuto: !!g.limits.auto_update,
                            });
                          }}
                        >
                          {t("groups.edit")}
                        </Menu.Item>
                        {!g.is_default && (
                          <Menu.Item color="red" leftSection={<IconTrash size={16} />} onClick={() => void remove(g)}>
                            {t("groups.remove")}
                          </Menu.Item>
                        )}
                      </Menu.Dropdown>
                    </Menu>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={edit !== null} onClose={() => setEdit(null)} title={edit?.id ? t("groups.editTitle") : t("groups.new")} size="lg" centered>
        {edit && (
          <form onSubmit={save}>
            <Stack>
              <TextInput
                label={t("groups.name")}
                required
                value={edit.form.name}
                onChange={(e) => setEdit({ ...edit, form: { ...edit.form, name: e.currentTarget.value } })}
              />
              <Textarea
                label={t("groups.description")}
                autosize
                minRows={1}
                value={edit.form.description}
                onChange={(e) => setEdit({ ...edit, form: { ...edit.form, description: e.currentTarget.value } })}
              />
              <Select
                label={t("groups.profile")}
                description={t("groups.profileHint")}
                data={(Object.keys(profileLabels) as AgentProfile[]).map((p) => ({ value: p, label: profileLabels[p] }))}
                value={edit.form.profile}
                allowDeselect={false}
                onChange={(v) => v && setEdit({ ...edit, form: { ...edit.form, profile: v as AgentProfile } })}
              />
              <Text fw={600} size="sm" mt="xs">
                {t("groups.limitsTitle")}
              </Text>
              <SimpleGrid cols={{ base: 1, sm: 2 }}>
                <LimitInput
                  label="CPU"
                  description={t("groups.f.cpu")}
                  max={100}
                  suffix=" %"
                  value={edit.form.limits.cpu_max_percent}
                  onChange={(v) => setLimit("cpu_max_percent", v)}
                />
                <Select
                  label={t("groups.f.priority")}
                  description={t("groups.f.priorityHint")}
                  placeholder={t("limits.defaults")}
                  clearable
                  data={priorities.map((value) => ({ value, label: t(`priority.${value}`) }))}
                  value={edit.form.limits.priority ?? null}
                  onChange={(v) => setLimit("priority", (v ?? undefined) as AgentLimits["priority"])}
                />
                <LimitInput
                  label={t("groups.f.memSoft")}
                  description={t("groups.f.memSoftHint")}
                  max={8192}
                  suffix=" MB"
                  value={edit.form.limits.memory_soft_mb}
                  onChange={(v) => setLimit("memory_soft_mb", v)}
                />
                <LimitInput
                  label={t("groups.f.memHard")}
                  description={t("groups.f.memHardHint")}
                  max={8192}
                  suffix=" MB"
                  value={edit.form.limits.memory_hard_mb}
                  onChange={(v) => setLimit("memory_hard_mb", v)}
                />
                <LimitInput
                  label={t("groups.f.eps")}
                  description={t("groups.f.noLimit")}
                  max={1000000}
                  suffix=""
                  value={edit.form.limits.max_eps}
                  onChange={(v) => setLimit("max_eps", v)}
                />
                <LimitInput
                  label={t("groups.f.bw")}
                  description={t("groups.f.bwHint")}
                  max={10000000}
                  suffix=" KiB/s"
                  value={edit.form.limits.max_send_kbps}
                  onChange={(v) => setLimit("max_send_kbps", v)}
                />
                <LimitInput
                  label={t("groups.f.buffer")}
                  description={t("groups.f.bufferHint")}
                  max={102400}
                  suffix=" MB"
                  value={edit.form.limits.buffer_max_mb}
                  onChange={(v) => setLimit("buffer_max_mb", v)}
                />
                <Select
                  label={t("groups.f.onFull")}
                  description={t("groups.f.onFullHint")}
                  placeholder={t("groups.f.onFullDefault")}
                  clearable
                  data={[
                    { value: "pause", label: t("groups.f.pause") },
                    { value: "drop_oldest", label: t("groups.f.dropOldest") },
                  ]}
                  value={edit.form.limits.buffer_on_full ?? null}
                  onChange={(v) => setLimit("buffer_on_full", (v ?? undefined) as AgentLimits["buffer_on_full"])}
                />
                <LimitInput
                  label={t("groups.f.heartbeat")}
                  description={t("groups.f.heartbeatHint")}
                  max={10080}
                  suffix=" min"
                  value={edit.form.limits.heartbeat_alert_min}
                  onChange={(v) => setLimit("heartbeat_alert_min", v)}
                />
              </SimpleGrid>
              <Checkbox
                label={t("groups.f.sysmon")}
                description={t("groups.f.sysmonHint")}
                checked={!!edit.form.limits.require_sysmon}
                onChange={(e) => setLimit("require_sysmon", e.currentTarget.checked || undefined)}
              />
              <Checkbox
                label={t("groups.f.protection")}
                description={t("groups.f.protectionHint")}
                checked={edit.form.limits.protection !== false}
                onChange={(e) => setLimit("protection", e.currentTarget.checked ? undefined : false)}
              />
              <Checkbox
                label={t("groups.f.iis")}
                description={t("groups.f.iisHint")}
                checked={!!edit.form.limits.iis_logs}
                onChange={(e) => setLimit("iis_logs", e.currentTarget.checked || undefined)}
              />
              <Checkbox
                label={t("groups.f.notifyReturn")}
                description={t("groups.f.notifyReturnHint")}
                disabled={!edit.form.limits.heartbeat_alert_min}
                checked={!!edit.form.limits.heartbeat_notify_return}
                onChange={(e) => setLimit("heartbeat_notify_return", e.currentTarget.checked || undefined)}
              />
              <Checkbox
                label={t("groups.f.autoUpdate")}
                description={
                  t("groups.f.autoUpdateHint") +
                  " " +
                  (agentVersion ? t("groups.f.autoUpdateServer", { v: agentVersion }) : t("groups.f.autoUpdateNoMsi"))
                }
                checked={!!edit.form.limits.auto_update}
                onChange={(e) => setLimit("auto_update", e.currentTarget.checked || undefined)}
              />
              {needPassword && (
                <ReauthPassword
                  label={t("yourPassword")}
                  description={t("groups.f.autoUpdatePassword")}
                  value={password}
                  onChange={setPassword}
                  required
                />
              )}
              <Button type="submit" loading={busy}>
                {t("save")}
              </Button>
            </Stack>
          </form>
        )}
      </Modal>
    </Stack>
  );
}
