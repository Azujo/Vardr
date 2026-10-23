// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Code,
  CopyButton,
  Group,
  List,
  Modal,
  NumberInput,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCheck, IconCopy, IconDownload, IconKey, IconPlus } from "@tabler/icons-react";
import { enrollApi, formatDate, groupsApi, type AgentGroup, type EnrollToken } from "../api";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth";
import { profileLabels } from "./GroupsPage";

// Ważność tokenu w godzinach (nazwy: agents: deploy.validity.<godziny>).
const validity = ["24", "168", "720", "2160"];

function tokenState(t: EnrollToken): { key: string; color: string } {
  if (t.revoked_at) return { key: "revoked", color: "gray" };
  if (new Date(t.expires_at) < new Date()) return { key: "expired", color: "gray" };
  if (t.max_uses > 0 && t.uses >= t.max_uses) return { key: "usedUp", color: "gray" };
  return { key: "active", color: "green" };
}

function msg(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

// Sekret tokenu pokazywany jeden raz, z paczką i poleceniem do wdrożenia masowego.
function SecretModal({ data, server, onClose }: { data: { token: EnrollToken; secret: string } | null; server: string; onClose: () => void }) {
  const { t } = useTranslation("agents");
  const [busy, setBusy] = useState("");
  if (!data) return null;
  const cmd = `vardr-agent.exe install -server ${server || location.hostname} -token ${data.secret}`;
  const download = async (kind: "msi" | "zip") => {
    setBusy(kind);
    try {
      if (kind === "msi") await enrollApi.downloadMSI(data.secret);
      else await enrollApi.downloadPackage(data.secret);
    } catch (e) {
      notifications.show({ color: "red", message: msg(e) });
    } finally {
      setBusy("");
    }
  };
  return (
    <Modal opened onClose={onClose} title={t("deploy.tokenTitle", { name: data.token.name })} size="lg" centered>
      <Stack>
        <Alert color="yellow" title={t("deploy.onlyNow")}>
          {t("deploy.onlyNowText")}
        </Alert>
        <Group wrap="nowrap" align="flex-start">
          <Code block style={{ flex: 1, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
            {data.secret}
          </Code>
          <CopyButton value={data.secret}>
            {({ copied, copy }) => (
              <Button variant="default" leftSection={copied ? <IconCheck size={16} /> : <IconCopy size={16} />} onClick={copy}>
                {copied ? t("copied") : t("copy")}
              </Button>
            )}
          </CopyButton>
        </Group>
        <Button leftSection={<IconDownload size={18} />} loading={busy === "msi"} onClick={() => void download("msi")}>
          {t("deploy.downloadMsi")}
        </Button>
        <Text size="sm" c="dimmed">
          {t("deploy.msiText")}
        </Text>
        <Button variant="subtle" size="xs" w="fit-content" loading={busy === "zip"} onClick={() => void download("zip")}>
          {t("deploy.zip")}
        </Button>
        <div>
          <Text size="sm" fw={500} mb={4}>
            {t("deploy.mass")}
          </Text>
          <Group wrap="nowrap" align="flex-start">
            <Code block style={{ flex: 1, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {cmd}
            </Code>
            <CopyButton value={cmd}>
              {({ copied, copy }) => (
                <Button variant="default" onClick={copy}>
                  {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                </Button>
              )}
            </CopyButton>
          </Group>
        </div>
        <Button variant="default" onClick={onClose}>
          {t("deploy.done")}
        </Button>
      </Stack>
    </Modal>
  );
}

export default function DeployPage() {
  const { t } = useTranslation("agents");
  const { can } = useAuth();
  const [tokens, setTokens] = useState<EnrollToken[]>([]);
  const [enabled, setEnabled] = useState(true);
  const [server, setServer] = useState("");
  const [error, setError] = useState("");
  const [open, setOpen] = useState(false);
  const [secret, setSecret] = useState<{ token: EnrollToken; secret: string } | null>(null);
  const [form, setForm] = useState({ name: "", groupId: "", hours: "168", maxUses: 0 });
  const [groups, setGroups] = useState<AgentGroup[]>([]);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    enrollApi
      .list()
      .then((r) => {
        setTokens(r.tokens);
        setEnabled(r.enabled);
        setServer(r.public_server);
      })
      .catch((e) => setError(msg(e)));
  }, []);
  useEffect(() => {
    if (can("deploy", "write")) load();
  }, [load, can]);
  useEffect(() => {
    groupsApi
      .list()
      .then((r) => {
        setGroups(r.groups);
        const def = r.groups.find((g) => g.is_default);
        if (def) setForm((f) => (f.groupId ? f : { ...f, groupId: String(def.id) }));
      })
      .catch(() => setGroups([]));
  }, []);

  if (!can("deploy", "write")) {
    return (
      <Alert color="blue" title={t("deploy.title")}>
        {t("deploy.noPerm")}
      </Alert>
    );
  }

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const g = groups.find((x) => String(x.id) === form.groupId);
      const res = await enrollApi.create({
        name: form.name,
        profile: g?.profile ?? "workstation",
        group_id: g?.id,
        valid_hours: Number(form.hours),
        max_uses: form.maxUses,
      });
      setOpen(false);
      setForm({ ...form, name: "", hours: "168", maxUses: 0 });
      setSecret(res);
      load();
    } catch (err) {
      notifications.show({ color: "red", message: msg(err) });
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (tok: EnrollToken) => {
    if (!window.confirm(t("deploy.revokeConfirm", { name: tok.name }))) return;
    try {
      await enrollApi.revoke(tok.id);
      load();
    } catch (e) {
      notifications.show({ color: "red", message: msg(e) });
    }
  };

  return (
    <Stack>
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>{t("deploy.title")}</Title>
          <Text c="dimmed" size="sm">
            {t("deploy.intro")}
          </Text>
        </div>
        <Button leftSection={<IconPlus size={18} />} onClick={() => setOpen(true)} disabled={!enabled}>
          {t("deploy.new")}
        </Button>
      </Group>
      {!enabled && (
        <Alert color="orange" title={t("deploy.disabled")}>
          {t("deploy.disabledText.0")}
          <Code>siem-pki agents-ca</Code>
          {t("deploy.disabledText.1")}
        </Alert>
      )}
      {error && <Alert color="red">{error}</Alert>}

      <Alert color="blue" variant="light" title={t("deploy.how")}>
        <List size="sm" spacing={2}>
          {[1, 2, 3, 4, 5].map((i) => (
            <List.Item key={i}>{t(`deploy.how${i}`)}</List.Item>
          ))}
        </List>
      </Alert>

      <Table.ScrollContainer minWidth={760}>
        <Table striped verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t("groups.name")}</Table.Th>
              <Table.Th>{t("deploy.groupProfile")}</Table.Th>
              <Table.Th>{t("deploy.installs")}</Table.Th>
              <Table.Th>{t("deploy.validUntil")}</Table.Th>
              <Table.Th>{t("deploy.createdBy")}</Table.Th>
              <Table.Th>{t("col.state")}</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {tokens.map((tok) => {
              const s = tokenState(tok);
              return (
                <Table.Tr key={tok.id}>
                  <Table.Td>
                    <Group gap={6} wrap="nowrap">
                      <IconKey size={16} opacity={0.6} />
                      <Text fw={500}>{tok.name}</Text>
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    {groups.find((g) => g.id === tok.group_id)?.name ?? t("deploy.defaultGroup")}
                    <Text size="xs" c="dimmed">
                      {profileLabels[tok.profile] ?? tok.profile}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    {tok.uses} / {tok.max_uses === 0 ? "∞" : tok.max_uses}
                  </Table.Td>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(tok.expires_at)}</Table.Td>
                  <Table.Td>{tok.created_by || "—"}</Table.Td>
                  <Table.Td>
                    <Badge color={s.color} variant="light">
                      {t(`deploy.state.${s.key}`)}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    {s.key === "active" && (
                      <Button size="xs" variant="subtle" color="red" onClick={() => void revoke(tok)}>
                        {t("revoke")}
                      </Button>
                    )}
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      {tokens.length === 0 && (
        <Text c="dimmed" size="sm">
          {t("deploy.none")}
        </Text>
      )}

      <Modal opened={open} onClose={() => setOpen(false)} title={t("deploy.newTitle")} centered>
        <form onSubmit={create}>
          <Stack>
            <TextInput
              label={t("groups.name")}
              description={t("deploy.nameHint")}
              required
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.currentTarget.value })}
            />
            <Select
              label={t("deploy.group")}
              description={t("deploy.groupHint")}
              data={groups.map((g) => ({ value: String(g.id), label: `${g.name} – ${profileLabels[g.profile]}` }))}
              value={form.groupId}
              allowDeselect={false}
              onChange={(v) => v && setForm({ ...form, groupId: v })}
            />
            <Select
              label={t("deploy.validity.label")}
              data={validity.map((value) => ({ value, label: t(`deploy.validity.${value}`) }))}
              value={form.hours}
              allowDeselect={false}
              onChange={(v) => v && setForm({ ...form, hours: v })}
            />
            <NumberInput
              label={t("deploy.maxUses")}
              description={t("deploy.maxUsesHint")}
              min={0}
              max={100000}
              value={form.maxUses}
              onChange={(v) => setForm({ ...form, maxUses: Number(v) || 0 })}
            />
            <Button type="submit" loading={busy}>
              {t("deploy.create")}
            </Button>
          </Stack>
        </form>
      </Modal>
      <SecretModal data={secret} server={server} onClose={() => setSecret(null)} />
    </Stack>
  );
}
