// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Code,
  CopyButton,
  Group,
  Menu,
  Modal,
  SegmentedControl,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconCheck,
  IconCopy,
  IconDots,
  IconKey,
  IconLock,
  IconLockOpen,
  IconShieldOff,
  IconUserPlus,
} from "@tabler/icons-react";
import { api, formatDate, profileName, roleLabels, type MFAPolicy, type Profile, type Role, type User } from "../api";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth";
import { ReauthPassword } from "../sso";


function errorMessage(err: unknown) {
  return err instanceof Error ? err.message : String(err);
}

// Hasło startowe pokazywane jeden raz – administrator przekazuje je użytkownikowi.
function TempPassword({ data, onClose }: { data: { user: User; temp_password: string } | null; onClose: () => void }) {
  const { t } = useTranslation("admin");
  return (
    <Modal opened={data !== null} onClose={onClose} title={t("users.temp.title")} centered>
      {data && (
        <Stack>
          <Text size="sm">
            {t("users.temp.text", { user: data.user.username })} <b>{t("users.temp.once")}</b>
          </Text>
          <Group>
            <Code fz="lg" style={{ flex: 1 }}>
              {data.temp_password}
            </Code>
            <CopyButton value={data.temp_password}>
              {({ copied, copy }) => (
                <Button leftSection={copied ? <IconCheck size={16} /> : <IconCopy size={16} />} onClick={copy}>
                  {copied ? t("copied") : t("copy")}
                </Button>
              )}
            </CopyButton>
          </Group>
          <Button variant="default" onClick={onClose}>
            {t("done")}
          </Button>
        </Stack>
      )}
    </Modal>
  );
}

export default function UsersPage() {
  const { t } = useTranslation("admin");
  const { user: me, can } = useAuth();
  const canWrite = can("users", "write");
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const roleOptions = profiles.length
    ? profiles.map((p) => ({ value: p.id, label: profileName(p.id, p.name) }))
    : Object.entries(roleLabels).map(([value, label]) => ({ value, label }));
  const isAdminProfile = (id: string) => profiles.find((p) => p.id === id)?.admin ?? id === "admin";
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [temp, setTemp] = useState<{ user: User; temp_password: string } | null>(null);
  const [form, setForm] = useState({ username: "", display_name: "", role: "viewer" as Role });
  const [busy, setBusy] = useState(false);
  const [mfa, setMfa] = useState<Record<string, string>>({});
  const [mfaAvailable, setMfaAvailable] = useState(false);
  const [policy, setPolicy] = useState<MFAPolicy>("all");
  const [policyEdit, setPolicyEdit] = useState<MFAPolicy | null>(null);
  const [mfaReset, setMfaReset] = useState<User | null>(null);
  const [password, setPassword] = useState("");

  const load = useCallback(() => {
    api
      .users()
      .then((r) => {
        setUsers(r.users);
        setMfa(r.mfa ?? {});
        setMfaAvailable(!!r.mfa_available);
        if (r.mfa_policy) setPolicy(r.mfa_policy);
      })
      .catch((e) => setError(errorMessage(e)));
    api
      .profiles()
      .then((r) => setProfiles(r.profiles))
      .catch(() => setProfiles([]));
  }, []);
  const savePolicy = async () => {
    if (!policyEdit) return;
    setBusy(true);
    try {
      await api.setSecuritySettings(policyEdit, password);
      notifications.show({ color: "green", message: t("users.policySaved") });
      setPolicyEdit(null);
      setPassword("");
      load();
    } catch (err) {
      notifications.show({ color: "red", message: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };
  const resetMFA = async () => {
    if (!mfaReset) return;
    setBusy(true);
    try {
      await api.resetUserMFA(mfaReset.id, password);
      notifications.show({ color: "green", message: t("users.mfaRemoved", { user: mfaReset.username }) });
      setMfaReset(null);
      setPassword("");
      load();
    } catch (err) {
      notifications.show({ color: "red", message: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };
  useEffect(load, [load]);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await api.createUser(form);
      setCreateOpen(false);
      setForm({ username: "", display_name: "", role: "viewer" });
      setTemp(res);
      load();
    } catch (err) {
      notifications.show({ color: "red", message: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  const update = async (u: User, patch: { role?: Role; disabled?: boolean }) => {
    try {
      await api.updateUser(u.id, patch);
      notifications.show({ color: "green", message: t("users.saved", { user: u.username }) });
      load();
    } catch (err) {
      notifications.show({ color: "red", message: errorMessage(err) });
    }
  };

  const reset = async (u: User) => {
    if (!window.confirm(t("users.resetConfirm", { user: u.username }))) return;
    try {
      setTemp(await api.resetPassword(u.id));
      load();
    } catch (err) {
      notifications.show({ color: "red", message: errorMessage(err) });
    }
  };

  const locked = (u: User) => u.locked_until && new Date(u.locked_until) > new Date();

  return (
    <Stack>
      <Group justify="space-between">
        <div>
          <Title order={2}>{t("users.title")}</Title>
          <Text c="dimmed" size="sm">
            {t("users.intro")}
          </Text>
        </div>
        {canWrite && (
          <Button leftSection={<IconUserPlus size={18} />} onClick={() => setCreateOpen(true)}>
            {t("users.new")}
          </Button>
        )}
      </Group>
      {error && <Alert color="red">{error}</Alert>}
      {mfaAvailable ? (
        <Group gap="sm" align="center">
          <Text size="sm" fw={500}>
            {t("users.mfaRequiredFrom")}
          </Text>
          <SegmentedControl
            size="xs"
            disabled={!canWrite}
            value={policy}
            onChange={(v) => {
              if (v !== policy) {
                setPassword("");
                setPolicyEdit(v as MFAPolicy);
              }
            }}
            data={[
              { value: "all", label: t("users.policy.all") },
              { value: "admins", label: t("users.policy.admins") },
              { value: "none", label: t("users.policy.none") },
            ]}
          />
        </Group>
      ) : (
        <Alert color="gray">
          {t("users.mfaUnavailable.0")}
          <Code>certs/mfa.key</Code>
          {t("users.mfaUnavailable.1")}
        </Alert>
      )}

      <Table.ScrollContainer minWidth={720}>
        <Table striped highlightOnHover verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t("users.col.login")}</Table.Th>
              <Table.Th>{t("users.col.name")}</Table.Th>
              <Table.Th>{t("users.col.profile")}</Table.Th>
              <Table.Th>{t("users.col.state")}</Table.Th>
              <Table.Th>MFA</Table.Th>
              <Table.Th>{t("users.col.lastLogin")}</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {users.map((u) => (
              <Table.Tr key={u.id}>
                <Table.Td>
                  <Group gap={6}>
                    <Text fw={500}>{u.username}</Text>
                    {u.source === "ldap" && (
                      <Tooltip label={t("users.adTip")}>
                        <Badge size="xs" color="cyan" variant="light">
                          AD
                        </Badge>
                      </Tooltip>
                    )}
                    {u.source === "oidc" && (
                      <Tooltip label={t("users.ssoTip")}>
                        <Badge size="xs" color="indigo" variant="light">
                          SSO
                        </Badge>
                      </Tooltip>
                    )}
                  </Group>
                </Table.Td>
                <Table.Td>{u.display_name || "—"}</Table.Td>
                <Table.Td>
                  <Select
                    size="xs"
                    w={180}
                    data={roleOptions}
                    value={u.role}
                    allowDeselect={false}
                    disabled={!canWrite || u.source === "ldap" || u.source === "oidc"}
                    title={u.source === "ldap" ? t("users.adProfile") : u.source === "oidc" ? t("users.ssoProfile") : undefined}
                    aria-label={t("users.profileOf", { user: u.username })}
                    onChange={(v) => v && v !== u.role && void update(u, { role: v as Role })}
                  />
                </Table.Td>
                <Table.Td>
                  <Group gap={4}>
                    {u.disabled ? (
                      <Badge color="gray">{t("users.state.disabled")}</Badge>
                    ) : (
                      <Badge color="green" variant="light">
                        {t("users.state.active")}
                      </Badge>
                    )}
                    {u.must_change_password && (
                      <Badge color="yellow" variant="light">
                        {t("users.state.initial")}
                      </Badge>
                    )}
                    {locked(u) && (
                      <Tooltip label={t("users.until", { date: formatDate(u.locked_until) })}>
                        <Badge color="orange" variant="light">
                          {t("users.state.locked")}
                        </Badge>
                      </Tooltip>
                    )}
                  </Group>
                </Table.Td>
                <Table.Td>
                  {mfa[String(u.id)] ? (
                    <Tooltip label={t("users.mfaOn", { date: formatDate(mfa[String(u.id)]) })}>
                      <Badge color="green" variant="light">
                        TOTP
                      </Badge>
                    </Tooltip>
                  ) : (
                    <Badge color={policy === "all" || (policy === "admins" && isAdminProfile(u.role)) ? "orange" : "gray"} variant="light">
                      {policy === "all" || (policy === "admins" && isAdminProfile(u.role)) ? t("users.mfaAtLogin") : t("users.mfaNone")}
                    </Badge>
                  )}
                </Table.Td>
                <Table.Td>
                  <Text size="sm">{formatDate(u.last_login_at)}</Text>
                </Table.Td>
                <Table.Td>
                  {canWrite && (
                  <Menu position="bottom-end">
                    <Menu.Target>
                      <ActionIcon variant="subtle" aria-label={t("users.actions", { user: u.username })}>
                        <IconDots size={18} />
                      </ActionIcon>
                    </Menu.Target>
                    <Menu.Dropdown>
                      {u.source !== "ldap" && u.source !== "oidc" && (
                        <Menu.Item leftSection={<IconKey size={16} />} onClick={() => void reset(u)}>
                          {t("users.newPassword")}
                        </Menu.Item>
                      )}
                      {mfa[String(u.id)] && (
                        <Menu.Item
                          leftSection={<IconShieldOff size={16} />}
                          onClick={() => {
                            setPassword("");
                            setMfaReset(u);
                          }}
                        >
                          {t("users.resetMfa")}
                        </Menu.Item>
                      )}
                      {u.id !== me?.id &&
                        (u.disabled ? (
                          <Menu.Item leftSection={<IconLockOpen size={16} />} onClick={() => void update(u, { disabled: false })}>
                            {t("users.enable")}
                          </Menu.Item>
                        ) : (
                          <Menu.Item
                            color="red"
                            leftSection={<IconLock size={16} />}
                            onClick={() => void update(u, { disabled: true })}
                          >
                            {t("users.disable")}
                          </Menu.Item>
                        ))}
                    </Menu.Dropdown>
                  </Menu>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={createOpen} onClose={() => setCreateOpen(false)} title={t("users.new")} centered>
        <form onSubmit={create}>
          <Stack>
            <TextInput
              label={t("users.col.login")}
              description={t("users.loginHint")}
              required
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.currentTarget.value })}
            />
            <TextInput
              label={t("users.displayName")}
              value={form.display_name}
              onChange={(e) => setForm({ ...form, display_name: e.currentTarget.value })}
            />
            <Select
              label={t("users.profile")}
              data={roleOptions}
              value={form.role}
              allowDeselect={false}
              onChange={(v) => v && setForm({ ...form, role: v as Role })}
            />
            <Button type="submit" loading={busy}>
              {t("users.create")}
            </Button>
          </Stack>
        </form>
      </Modal>
      <TempPassword data={temp} onClose={() => setTemp(null)} />
      <Modal opened={!!policyEdit} onClose={() => setPolicyEdit(null)} title={t("users.policyTitle")} centered>
        {policyEdit && (
          <Stack>
            <Text size="sm">
              {policyEdit === "none" ? t("users.policyNone") : policyEdit === "all" ? t("users.policyAll") : t("users.policyAdmins")}
            </Text>
            <ReauthPassword label={t("yourPassword")} value={password} onChange={setPassword} autoFocus />
            <Button color={policyEdit === "none" ? "red" : undefined} loading={busy} disabled={!password} onClick={() => void savePolicy()}>
              {t("save")}
            </Button>
          </Stack>
        )}
      </Modal>
      <Modal opened={!!mfaReset} onClose={() => setMfaReset(null)} title={t("users.resetMfaTitle", { user: mfaReset?.username ?? "" })} centered>
        {mfaReset && (
          <Stack>
            <Text size="sm">
              {t("users.resetMfaText")}
            </Text>
            <ReauthPassword label={t("yourPassword")} value={password} onChange={setPassword} autoFocus />
            <Button color="red" loading={busy} disabled={!password} onClick={() => void resetMFA()}>
              {t("users.reset")}
            </Button>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
