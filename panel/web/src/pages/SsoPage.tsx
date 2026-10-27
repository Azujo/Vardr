// SPDX-License-Identifier: AGPL-3.0-or-later

// Logowanie SSO (OpenID Connect, Microsoft Entra ID): rejestracja aplikacji
// u dostawcy, powiązania grup z profilami uprawnień (w kolejności – pierwsza
// pasująca wygrywa) i sprawdzenie konfiguracji dostawcy.
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
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconArrowDown, IconArrowUp, IconPlugConnected, IconPlus, IconTrash } from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import { api, profileName as builtinName, type OIDCConfig, type Profile } from "../api";
import { serverText } from "../i18n";
import { useAuth } from "../auth";
import { ReauthPassword } from "../sso";

const callbackPath = "/api/v1/auth/oidc/callback";

const empty: OIDCConfig = {
  enabled: false,
  issuer: "",
  client_id: "",
  redirect_url: "",
  button_label: "",
  mappings: [],
};

export default function SsoPage() {
  const { t } = useTranslation("admin");
  const { can } = useAuth();
  const canEdit = can("users", "write");
  const [available, setAvailable] = useState(true);
  const [cfg, setCfg] = useState<OIDCConfig>(empty);
  const [hasSecret, setHasSecret] = useState(false);
  const [savedEnabled, setSavedEnabled] = useState(false);
  const [secret, setSecret] = useState("");
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState("");
  const [saveOpen, setSaveOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(() => {
    api
      .oidcSettings()
      .then((r) => {
        setAvailable(r.available);
        if (r.config) {
          setCfg({ ...r.config, redirect_url: r.config.redirect_url || window.location.origin + callbackPath });
          setSavedEnabled(r.config.enabled);
        }
        setHasSecret(!!r.has_secret);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
    api
      .profiles()
      .then((r) => setProfiles(r.profiles))
      .catch(() => setProfiles([]));
  }, []);
  useEffect(load, [load]);

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
  const setMapping = (i: number, patch: Partial<OIDCConfig["mappings"][number]>) =>
    setCfg({ ...cfg, mappings: cfg.mappings.map((m, j) => (j === i ? { ...m, ...patch } : m)) });
  const move = (i: number, d: number) => {
    const m = [...cfg.mappings];
    [m[i], m[i + d]] = [m[i + d], m[i]];
    setCfg({ ...cfg, mappings: m });
  };

  if (!available) {
    return (
      <Alert color="gray" title={t("sso.unavailable")}>
        {t("sso.unavailableText.0")}
        <Code>certs/mfa.key</Code>
        {t("sso.unavailableText.1")}
      </Alert>
    );
  }

  return (
    <Stack maw={1100}>
      <div>
        <Title order={2}>{t("sso.title")}</Title>
        <Text c="dimmed" size="sm" maw={860}>
          {t("sso.intro")}
        </Text>
      </div>
      {error && <Alert color="red">{error}</Alert>}

      <Card withBorder>
        <Stack gap="sm">
          <Group justify="space-between">
            <Title order={4}>{t("sso.step1")}</Title>
            <Switch
              label={(cfg.enabled ? t("sso.enabled") : t("sso.disabled")) + (cfg.enabled !== savedEnabled ? t("sso.unsaved") : "")}
              checked={cfg.enabled}
              disabled={!canEdit}
              onChange={(e) => setCfg({ ...cfg, enabled: e.currentTarget.checked })}
            />
          </Group>
          <Text size="sm" c="dimmed">
            {t("sso.registerHint")}
          </Text>
          <TextInput
            label={t("sso.redirect")}
            description={t("sso.redirectHint")}
            value={cfg.redirect_url}
            disabled={!canEdit}
            styles={{ input: { fontFamily: "monospace" } }}
            onChange={(e) => setCfg({ ...cfg, redirect_url: e.currentTarget.value })}
          />
          <TextInput
            label={t("sso.issuer")}
            description={t("sso.issuerHint")}
            placeholder="https://login.microsoftonline.com/<tenant-id>/v2.0"
            value={cfg.issuer}
            disabled={!canEdit}
            onChange={(e) => setCfg({ ...cfg, issuer: e.currentTarget.value })}
          />
          <Group grow align="flex-start">
            <TextInput
              label={t("sso.clientId")}
              description={t("sso.clientIdHint")}
              value={cfg.client_id}
              disabled={!canEdit}
              onChange={(e) => setCfg({ ...cfg, client_id: e.currentTarget.value })}
            />
            <PasswordInput
              label={t("sso.secret")}
              description={hasSecret ? t("sso.secretSaved") : t("sso.secretNew")}
              value={secret}
              disabled={!canEdit}
              autoComplete="new-password"
              onChange={(e) => setSecret(e.currentTarget.value)}
            />
          </Group>
          <TextInput
            label={t("sso.button")}
            description={t("sso.buttonHint")}
            placeholder="Microsoft Entra ID"
            maxLength={60}
            w={360}
            value={cfg.button_label}
            disabled={!canEdit}
            onChange={(e) => setCfg({ ...cfg, button_label: e.currentTarget.value })}
          />
          {canEdit && (
            <Group gap="xs">
              <Button
                variant="light"
                leftSection={<IconPlugConnected size={16} />}
                loading={busy === "test"}
                onClick={() =>
                  void run("test", async () => {
                    const r = await api.oidcTest(cfg, secret);
                    setTestResult({ ok: r.ok, text: r.ok ? t("sso.testOk") : r.error ? serverText(r.error, r.error_en) : t("sso.error") });
                  })
                }
              >
                {t("sso.test")}
              </Button>
              {testResult && <Badge color={testResult.ok ? "green" : "red"}>{testResult.ok ? t("sso.works") : t("sso.error")}</Badge>}
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
          <Title order={4}>{t("sso.step2")}</Title>
          <Text size="sm" c="dimmed">
            {t("sso.groupsIntro")}
          </Text>
          {cfg.mappings.length === 0 && (
            <Text size="sm" c="dimmed">
              {t("sso.noMappings")}
            </Text>
          )}
          {cfg.mappings.map((m, i) => (
            <Group key={i} gap="xs" align="flex-end" wrap="nowrap">
              <Badge variant="light" w={28} p={0} mb={8}>
                {i + 1}
              </Badge>
              <TextInput
                label={i === 0 ? t("sso.col.group") : undefined}
                placeholder="00000000-0000-0000-0000-000000000000"
                w={330}
                styles={{ input: { fontFamily: "monospace", fontSize: 12 } }}
                value={m.group}
                disabled={!canEdit}
                onChange={(e) => setMapping(i, { group: e.currentTarget.value.trim() })}
              />
              <TextInput
                label={i === 0 ? t("sso.col.name") : undefined}
                placeholder={t("sso.namePlaceholder")}
                w={220}
                value={m.name}
                disabled={!canEdit}
                onChange={(e) => setMapping(i, { name: e.currentTarget.value })}
              />
              <Select
                label={i === 0 ? t("sso.col.profile") : undefined}
                w={220}
                disabled={!canEdit}
                data={profiles.map((p) => ({ value: p.id, label: builtinName(p.id, p.name) }))}
                value={m.profile || null}
                onChange={(v) => setMapping(i, { profile: v ?? "" })}
              />
              {canEdit && (
                <Group gap={2} mb={4} wrap="nowrap">
                  <ActionIcon variant="subtle" disabled={i === 0} onClick={() => move(i, -1)} aria-label={t("sso.up")}>
                    <IconArrowUp size={14} />
                  </ActionIcon>
                  <ActionIcon
                    variant="subtle"
                    disabled={i === cfg.mappings.length - 1}
                    onClick={() => move(i, 1)}
                    aria-label={t("sso.down")}
                  >
                    <IconArrowDown size={14} />
                  </ActionIcon>
                  <Tooltip label={t("sso.removeMapping")}>
                    <ActionIcon
                      variant="subtle"
                      color="red"
                      onClick={() => setCfg({ ...cfg, mappings: cfg.mappings.filter((_, j) => j !== i) })}
                    >
                      <IconTrash size={14} />
                    </ActionIcon>
                  </Tooltip>
                </Group>
              )}
            </Group>
          ))}
          {canEdit && (
            <Group>
              <Button
                variant="light"
                size="xs"
                leftSection={<IconPlus size={14} />}
                onClick={() => setCfg({ ...cfg, mappings: [...cfg.mappings, { group: "", name: "", profile: "" }] })}
              >
                {t("sso.addMapping")}
              </Button>
            </Group>
          )}
          <Alert color="blue" variant="light">
            {t("sso.mfaNote")}
          </Alert>
        </Stack>
      </Card>

      {canEdit && (
        <Group>
          <Button
            onClick={() => {
              setPassword("");
              setSaveOpen(true);
            }}
          >
            {t("sso.save")}
          </Button>
        </Group>
      )}

      <Modal opened={saveOpen} onClose={() => setSaveOpen(false)} title={t("sso.saveTitle")} centered>
        <Stack>
          <Text size="sm">{t("sso.saveText")}</Text>
          <ReauthPassword label={t("yourPassword")} value={password} onChange={setPassword} autoFocus />
          <Button
            loading={busy === "save"}
            disabled={!password}
            onClick={() =>
              void run("save", async () => {
                await api.saveOidcSettings(cfg, secret, password);
                notifications.show({ color: "green", message: t("sso.saved") });
                setSaveOpen(false);
                setSecret("");
                setTestResult(null);
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
