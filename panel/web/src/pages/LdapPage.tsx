// SPDX-License-Identifier: AGPL-3.0-or-later

// Logowanie domenowe (AD przez LDAPS): połączenie z kontem usługowym,
// kreator grup (OU → grupy → profil uprawnień, w kolejności) i podgląd
// konta – jaki profil dostanie przy logowaniu.
import { useCallback, useEffect, useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Card,
  Code,
  Group,
  Modal,
  PasswordInput,
  Select,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
  Textarea,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconArrowDown, IconArrowUp, IconPlugConnected, IconSearch, IconTrash, IconUsersGroup } from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import { api, profileName as builtinName, type LDAPAccountCheck, type LDAPConfig, type LDAPGroup, type Profile } from "../api";
import { serverText } from "../i18n";
import { useAuth } from "../auth";

const empty: LDAPConfig = {
  enabled: false,
  urls: [],
  ca_pem: "",
  tls_server_name: "",
  bind_dn: "",
  base_dn: "",
  groups_base_dn: "",
  mappings: [],
};

export default function LdapPage() {
  const { t } = useTranslation("admin");
  const { can } = useAuth();
  const canEdit = can("users", "write");
  const [available, setAvailable] = useState(true);
  const [cfg, setCfg] = useState<LDAPConfig>(empty);
  const [urlsText, setUrlsText] = useState("");
  const [hasPassword, setHasPassword] = useState(false);
  const [savedEnabled, setSavedEnabled] = useState(false);
  const [bindPassword, setBindPassword] = useState("");
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [groups, setGroups] = useState<LDAPGroup[] | null>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [checkLogin, setCheckLogin] = useState("");
  const [check, setCheck] = useState<LDAPAccountCheck | null>(null);
  const [busy, setBusy] = useState("");
  const [saveOpen, setSaveOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(() => {
    api
      .ldapSettings()
      .then((r) => {
        setAvailable(r.available);
        if (r.config) {
          setCfg(r.config);
          setSavedEnabled(r.config.enabled);
          setUrlsText(r.config.urls.join("\n"));
        }
        setHasPassword(!!r.has_password);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
    api
      .profiles()
      .then((r) => setProfiles(r.profiles))
      .catch(() => setProfiles([]));
  }, []);
  useEffect(load, [load]);

  const draft = (): LDAPConfig => ({
    ...cfg,
    urls: urlsText
      .split(/[\n,]/)
      .map((u) => u.trim())
      .filter(Boolean),
  });
  const run = async (what: string, fn: () => Promise<void>) => {
    setBusy(what);
    try {
      await fn();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy("");
    }
  };
  const profileName = (id: string) => builtinName(id, profiles.find((p) => p.id === id)?.name ?? id);
  const mapped = new Map(cfg.mappings.map((m) => [m.sid, m]));
  const setMapping = (g: LDAPGroup, profile: string | null) => {
    const rest = cfg.mappings.filter((m) => m.sid !== g.sid);
    if (!profile) setCfg({ ...cfg, mappings: rest });
    else if (mapped.has(g.sid)) setCfg({ ...cfg, mappings: cfg.mappings.map((m) => (m.sid === g.sid ? { ...m, profile } : m)) });
    else setCfg({ ...cfg, mappings: [...rest, { sid: g.sid, name: g.name, dn: g.dn, profile }] });
  };
  const move = (i: number, d: number) => {
    const m = [...cfg.mappings];
    [m[i], m[i + d]] = [m[i + d], m[i]];
    setCfg({ ...cfg, mappings: m });
  };

  if (!available) {
    return (
      <Alert color="gray" title={t("ldap.unavailable")}>
        {t("ldap.unavailableText.0")}
        <Code>certs/mfa.key</Code>
        {t("ldap.unavailableText.1")}
      </Alert>
    );
  }

  return (
    <Stack maw={1100}>
      <div>
        <Title order={2}>{t("ldap.title")}</Title>
        <Text c="dimmed" size="sm" maw={860}>
          {t("ldap.intro")}
        </Text>
      </div>
      {error && <Alert color="red">{error}</Alert>}

      <Card withBorder>
        <Stack gap="sm">
          <Group justify="space-between">
            <Title order={4}>{t("ldap.step1")}</Title>
            <Switch
              label={
                (cfg.enabled ? t("ldap.enabled") : t("ldap.disabled")) + (cfg.enabled !== savedEnabled ? t("ldap.unsaved") : "")
              }
              checked={cfg.enabled}
              disabled={!canEdit}
              onChange={(e) => setCfg({ ...cfg, enabled: e.currentTarget.checked })}
            />
          </Group>
          <Group grow align="flex-start">
            <Textarea
              label={t("ldap.urls")}
              description={t("ldap.urlsHint")}
              autosize
              minRows={2}
              value={urlsText}
              disabled={!canEdit}
              onChange={(e) => setUrlsText(e.currentTarget.value)}
            />
            <TextInput
              label={t("ldap.serverName")}
              description={t("ldap.serverNameHint")}
              value={cfg.tls_server_name}
              disabled={!canEdit}
              onChange={(e) => setCfg({ ...cfg, tls_server_name: e.currentTarget.value })}
            />
          </Group>
          <Textarea
            label={t("ldap.ca")}
            description={t("ldap.caHint")}
            autosize
            minRows={2}
            maxRows={8}
            styles={{ input: { fontFamily: "monospace", fontSize: 11 } }}
            value={cfg.ca_pem}
            disabled={!canEdit}
            onChange={(e) => setCfg({ ...cfg, ca_pem: e.currentTarget.value })}
          />
          <Group grow align="flex-start">
            <TextInput
              label={t("ldap.bind")}
              description={t("ldap.bindHint")}
              value={cfg.bind_dn}
              disabled={!canEdit}
              onChange={(e) => setCfg({ ...cfg, bind_dn: e.currentTarget.value })}
            />
            <PasswordInput
              label={t("ldap.bindPassword")}
              description={hasPassword ? t("ldap.bindPasswordSaved") : t("ldap.bindPasswordNew")}
              value={bindPassword}
              disabled={!canEdit}
              onChange={(e) => setBindPassword(e.currentTarget.value)}
            />
            <TextInput
              label={t("ldap.base")}
              description={t("ldap.baseHint")}
              value={cfg.base_dn}
              disabled={!canEdit}
              onChange={(e) => setCfg({ ...cfg, base_dn: e.currentTarget.value })}
            />
          </Group>
          {canEdit && (
            <Group gap="xs">
              <Button
                variant="light"
                leftSection={<IconPlugConnected size={16} />}
                loading={busy === "test"}
                onClick={() =>
                  void run("test", async () => {
                    const r = await api.ldapTest(draft(), bindPassword);
                    setTestResult({ ok: r.ok, text: r.ok ? t("ldap.testOk") : (r.error ? serverText(r.error, r.error_en) : t("ldap.error")) });
                  })
                }
              >
                {t("ldap.test")}
              </Button>
              {testResult && <Badge color={testResult.ok ? "green" : "red"}>{testResult.ok ? t("ldap.works") : t("ldap.error")}</Badge>}
              {testResult && (
                <Text size="xs" c={testResult.ok ? "dimmed" : "red"} maw={600}>
                  {testResult.text}
                </Text>
              )}
            </Group>
          )}
        </Stack>
      </Card>

      <Card withBorder>
        <Stack gap="sm">
          <Title order={4}>{t("ldap.step2")}</Title>
          <Text size="sm" c="dimmed">
            {t("ldap.groupsIntro")}
          </Text>
          <Group align="flex-end">
            <TextInput
              label={t("ldap.groupsOu")}
              placeholder="OU=Vardr,OU=Grupy,DC=firma,DC=pl"
              w={460}
              value={cfg.groups_base_dn}
              disabled={!canEdit}
              onChange={(e) => setCfg({ ...cfg, groups_base_dn: e.currentTarget.value })}
            />
            {canEdit && (
              <Button
                variant="light"
                leftSection={<IconUsersGroup size={16} />}
                loading={busy === "groups"}
                onClick={() => void run("groups", async () => setGroups((await api.ldapGroups(draft(), bindPassword)).groups))}
              >
                {t("ldap.showGroups")}
              </Button>
            )}
          </Group>
          {groups && (
            <Table striped verticalSpacing={4}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t("ldap.col.group")}</Table.Th>
                  <Table.Th>{t("ldap.col.members")}</Table.Th>
                  <Table.Th>{t("ldap.col.profile")}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {groups.length === 0 && (
                  <Table.Tr>
                    <Table.Td colSpan={3}>
                      <Text size="sm" c="dimmed">
                        {t("ldap.noGroups")}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                )}
                {groups.map((g) => (
                  <Table.Tr key={g.sid}>
                    <Table.Td>
                      <Text size="sm" fw={500}>
                        {g.name}
                      </Text>
                      <Text size="xs" c="dimmed">
                        {g.description || g.dn}
                      </Text>
                    </Table.Td>
                    <Table.Td>{g.members}</Table.Td>
                    <Table.Td>
                      <Select
                        size="xs"
                        w={220}
                        placeholder={t("ldap.noAccess")}
                        clearable
                        disabled={!canEdit}
                        data={profiles.map((p) => ({ value: p.id, label: builtinName(p.id, p.name) }))}
                        value={mapped.get(g.sid)?.profile ?? null}
                        onChange={(v) => setMapping(g, v)}
                      />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          )}
          <Text size="sm" fw={500}>
            {t("ldap.mappings")}
          </Text>
          {cfg.mappings.length === 0 ? (
            <Text size="sm" c="dimmed">
              {t("ldap.noMappings")}
            </Text>
          ) : (
            <Stack gap={4}>
              {cfg.mappings.map((m, i) => (
                <Group key={m.sid} gap="xs">
                  <Badge variant="light" w={28} p={0}>
                    {i + 1}
                  </Badge>
                  <Text size="sm" w={260} truncate>
                    {m.name}
                  </Text>
                  <Text size="sm">→</Text>
                  <Badge color={profiles.find((p) => p.id === m.profile)?.admin ? "grape" : "blue"} variant="light">
                    {profileName(m.profile)}
                  </Badge>
                  {canEdit && (
                    <>
                      <ActionIcon variant="subtle" disabled={i === 0} onClick={() => move(i, -1)} aria-label={t("ldap.up")}>
                        <IconArrowUp size={14} />
                      </ActionIcon>
                      <ActionIcon variant="subtle" disabled={i === cfg.mappings.length - 1} onClick={() => move(i, 1)} aria-label={t("ldap.down")}>
                        <IconArrowDown size={14} />
                      </ActionIcon>
                      <Tooltip label={t("ldap.removeMapping")}>
                        <ActionIcon
                          variant="subtle"
                          color="red"
                          onClick={() => setCfg({ ...cfg, mappings: cfg.mappings.filter((x) => x.sid !== m.sid) })}
                        >
                          <IconTrash size={14} />
                        </ActionIcon>
                      </Tooltip>
                    </>
                  )}
                  <Text size="xs" c="dimmed" ff="monospace">
                    {m.sid}
                  </Text>
                </Group>
              ))}
            </Stack>
          )}
        </Stack>
      </Card>

      {canEdit && (
        <Card withBorder>
          <Stack gap="sm">
            <Title order={4}>{t("ldap.step3")}</Title>
            <Group align="flex-end">
              <TextInput
                label={t("ldap.login")}
                placeholder={t("ldap.loginPlaceholder")}
                w={260}
                value={checkLogin}
                onChange={(e) => setCheckLogin(e.currentTarget.value)}
              />
              <Button
                variant="light"
                leftSection={<IconSearch size={16} />}
                loading={busy === "check"}
                disabled={!checkLogin}
                onClick={() => void run("check", async () => setCheck(await api.ldapCheck(draft(), bindPassword, checkLogin)))}
              >
                {t("ldap.check")}
              </Button>
            </Group>
            {check && !check.found && <Alert color="orange">{t("ldap.notFound")}</Alert>}
            {check?.found && check.account && (
              <Alert color={check.profile ? "green" : "orange"}>
                <Text size="sm">
                  <b>{check.account.display_name || check.account.login}</b> ({check.account.upn || check.account.login})
                  {check.account.disabled && t("ldap.accountDisabled")}; {t("ldap.securityGroups", { n: check.groups })}
                </Text>
                <Text size="sm">
                  {check.profile
                    ? t("ldap.willGet", { profile: profileName(check.profile), group: check.matched[0]?.name })
                    : t("ldap.noLogin")}
                  {check.matched.length > 1 && ` ${t("ldap.alsoMatches", { list: check.matched.slice(1).map((m) => m.name).join(", ") })}`}
                </Text>
              </Alert>
            )}
          </Stack>
        </Card>
      )}

      {canEdit && (
        <Group>
          <Button
            onClick={() => {
              setPassword("");
              setSaveOpen(true);
            }}
          >
            {t("ldap.save")}
          </Button>
        </Group>
      )}

      <Modal opened={saveOpen} onClose={() => setSaveOpen(false)} title={t("ldap.saveTitle")} centered>
        <Stack>
          <Text size="sm">{t("ldap.saveText")}</Text>
          <PasswordInput label={t("yourPassword")} value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoFocus />
          <Button
            loading={busy === "save"}
            disabled={!password}
            onClick={() =>
              void run("save", async () => {
                await api.saveLdapSettings(draft(), bindPassword, password);
                notifications.show({ color: "green", message: t("ldap.saved") });
                setSaveOpen(false);
                setBindPassword("");
                load();
              })
            }
          >
            {t("save")}
          </Button>
        </Stack>
      </Modal>
    </Stack>
  );
}
