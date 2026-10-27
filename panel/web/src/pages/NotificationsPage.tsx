// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  Code,
  CopyButton,
  Group,
  Modal,
  MultiSelect,
  Select,
  PasswordInput,
  SegmentedControl,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAnchor, IconBell, IconCheck, IconCopy, IconKey, IconPlus, IconSend, IconSignature, IconTrash } from "@tabler/icons-react";
import {
  ApiError,
  alertsApi,
  formatDate,
  levelLabels,
  notifyApi,
  notifyEventLabels,
  ruleText,
  settingsApi,
  type AlertFilter,
  type AlertLevel,
  type ChannelKind,
  type ChannelRequest,
  type NotifyChannel,
  type NotifyEvent,
  type NotifyLogEntry,
} from "../api";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth";
import { languages } from "../i18n";
import { ReauthPassword } from "../sso";

const allEvents: NotifyEvent[] = ["alert", "incident", "health", "anchor"];

const kindLabels: Record<ChannelKind, string> = { discord: "Discord", teams: "Power Automate / Teams", webhook: "Webhook (JSON)" };
// Podpis HMAC – kanały, których odbiorca może go sprawdzić (nie Discord).
const signable = (k: ChannelKind) => k === "webhook" || k === "teams";

// Sekret podpisu pokazywany raz – przy utworzeniu kanału albo nowym sekrecie.
function SigningSecret({ data, onClose }: { data: { channel: string; secret: string } | null; onClose: () => void }) {
  const { t } = useTranslation("admin");
  return (
    <Modal opened={data !== null} onClose={onClose} title={t("notify.secretTitle", { name: data?.channel ?? "" })} centered size="lg">
      {data && (
        <Stack>
          <Text size="sm">
            {t("notify.secretText")} <b>{t("notify.secretOnce")}</b>
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
          <Text size="sm" c="dimmed">
            {t("notify.secretHow")}
          </Text>
          <Button variant="default" onClick={onClose}>
            {t("done")}
          </Button>
        </Stack>
      )}
    </Modal>
  );
}

function errMsg(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

const levels: AlertLevel[] = ["informational", "low", "medium", "high", "critical"];

// Filtr alertów detekcji na kanale: od poziomu i wybór reguł.
function AlertFilterEditor({
  value,
  rules,
  onSave,
}: {
  value: AlertFilter;
  rules: { value: string; label: string }[];
  onSave: (f: AlertFilter) => void;
}) {
  const { t } = useTranslation("admin");
  const [f, setF] = useState<AlertFilter>(value);
  useEffect(() => setF(value), [value]);
  const mode = f.rules_mode ?? "all";
  const changed = JSON.stringify(f) !== JSON.stringify(value);
  return (
    <Group gap="xs" align="flex-end" wrap="wrap">
      <Select
        size="xs"
        w={170}
        label={t("notify.minLevel")}
        allowDeselect={false}
        data={levels.map((l) => ({ value: l, label: levelLabels[l].label }))}
        value={f.min_level ?? "informational"}
        onChange={(v) => setF({ ...f, min_level: v === "informational" ? undefined : (v as AlertLevel) })}
      />
      <Select
        size="xs"
        w={200}
        label={t("notify.rules")}
        allowDeselect={false}
        data={[
          { value: "all", label: t("notify.rulesAll") },
          { value: "only", label: t("notify.rulesOnly") },
          { value: "except", label: t("notify.rulesExcept") },
        ]}
        value={mode}
        onChange={(v) =>
          setF(v === "all" ? { min_level: f.min_level } : { ...f, rules_mode: v as "only" | "except", rules: f.rules ?? [] })
        }
      />
      {mode !== "all" && (
        <MultiSelect
          size="xs"
          miw={260}
          maw={520}
          label={mode === "only" ? t("notify.onlyFrom") : t("notify.notFrom")}
          searchable
          data={rules}
          value={f.rules ?? []}
          onChange={(v) => setF({ ...f, rules: v })}
        />
      )}
      {changed && (
        <Button size="xs" disabled={mode !== "all" && !(f.rules ?? []).length} onClick={() => onSave(f)}>
          {t("notify.saveFilter")}
        </Button>
      )}
    </Group>
  );
}

// Kanały powiadomień: dokąd Vardr wysyła wiadomości poza system.
export default function NotificationsPage() {
  const { t } = useTranslation("admin");
  const [channels, setChannels] = useState<NotifyChannel[]>([]);
  const [log, setLog] = useState<NotifyLogEntry[]>([]);
  const [anchorHour, setAnchorHour] = useState(-1);
  const [relay, setRelay] = useState(true);
  const [error, setError] = useState("");
  const [adding, setAdding] = useState(false);
  const emptyForm = { name: "", kind: "discord" as ChannelKind, url: "", events: ["alert", "health", "anchor"] as NotifyEvent[], sign: false };
  const [form, setForm] = useState(emptyForm);
  const [secret, setSecret] = useState<{ channel: string; secret: string } | null>(null);
  // Zmiana wymagająca hasła (wyłączenie, rezygnacja z powiadomień, usunięcie).
  const [pending, setPending] = useState<{ label: string; run: (pw: string) => Promise<void> } | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [ruleOptions, setRuleOptions] = useState<{ value: string; label: string }[]>([]);
  const { can } = useAuth();
  const [sysLang, setSysLang] = useState<{ language: string; supported: string[]; editable: boolean } | null>(null);
  useEffect(() => {
    settingsApi
      .language()
      .then(setSysLang)
      .catch(() => setSysLang(null));
  }, []);
  const changeSysLang = async (language: string) => {
    try {
      await settingsApi.setLanguage(language);
      setSysLang((s) => s && { ...s, language });
      notifications.show({ color: "green", message: t("notify.systemLanguageSaved", { language: languages[language] ?? language }) });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };
  useEffect(() => {
    alertsApi
      .rules()
      .then((r) => setRuleOptions(r.rules.map((x) => ({ value: x.id, label: ruleText(x).title }))))
      .catch(() => setRuleOptions([]));
  }, []);

  const load = useCallback(() => {
    notifyApi
      .list()
      .then((r) => {
        setChannels(r.channels);
        setLog(r.log);
        setAnchorHour(r.anchor_hour);
        setRelay(r.relay_configured);
        setError("");
      })
      .catch((e) => setError(errMsg(e)));
  }, []);
  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [load]);

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await notifyApi.create({ ...form, sign: signable(form.kind) && form.sign, enabled: true });
      notifications.show({ color: "green", message: t("notify.added") });
      setAdding(false);
      setForm(emptyForm);
      if (res.signing_secret) setSecret({ channel: res.channel.name, secret: res.signing_secret });
      load();
    } catch (err) {
      notifications.show({ color: "red", message: errMsg(err) });
    } finally {
      setBusy(false);
    }
  };

  // Zmiana kanału; gdy serwer zażąda hasła – okno z hasłem i ponowienie.
  const update = async (c: NotifyChannel, patch: Partial<ChannelRequest>, label: string) => {
    const req: ChannelRequest = { name: c.name, events: c.events, alert_filter: c.alert_filter, enabled: c.enabled, ...patch };
    const done = (res: { signing_secret?: string }) => {
      if (res.signing_secret) setSecret({ channel: c.name, secret: res.signing_secret });
      load();
    };
    try {
      done(await notifyApi.update(c.id, req));
    } catch (e) {
      if (e instanceof ApiError && e.code === "reauth_required") {
        setPending({
          label,
          run: async (pw) => {
            done(await notifyApi.update(c.id, { ...req, password: pw }));
          },
        });
      } else notifications.show({ color: "red", message: errMsg(e) });
    }
  };

  const confirm = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pending) return;
    setBusy(true);
    try {
      await pending.run(password);
      notifications.show({ color: "green", message: t("notify.changed") });
      setPending(null);
      setPassword("");
    } catch (err) {
      notifications.show({ color: "red", message: errMsg(err) });
    } finally {
      setBusy(false);
    }
  };

  const action = async (fn: () => Promise<{ message: string }>, done: string) => {
    try {
      await fn();
      notifications.show({ color: "green", message: done });
    } catch (e) {
      notifications.show({ color: "red", message: errMsg(e) });
    } finally {
      load();
    }
  };

  return (
    <Stack>
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>{t("notify.title")}</Title>
          <Text c="dimmed" size="sm" maw={820}>
            {t("notify.intro", { at: anchorHour >= 0 ? t("notify.at", { h: anchorHour }) : "" })}
          </Text>
        </div>
        <Group>
          <Button variant="light" leftSection={<IconAnchor size={18} />} onClick={() => void action(notifyApi.sendAnchor, t("notify.anchorSent"))}>
            {t("notify.sendAnchor")}
          </Button>
          <Button leftSection={<IconPlus size={18} />} onClick={() => setAdding(true)}>
            {t("notify.add")}
          </Button>
        </Group>
      </Group>
      {error && <Alert color="red">{error}</Alert>}
      {!relay && (
        <Alert color="orange">
          {t("notify.noRelay")}
        </Alert>
      )}
      {channels.length > 0 && !channels.some((c) => c.enabled && c.events.includes("alert")) && (
        <Alert color="orange" icon={<IconBell />}>
          {t("notify.noAlertChannel", { event: notifyEventLabels.alert })}
        </Alert>
      )}
      {channels.length === 0 && (
        <Alert color="gray" icon={<IconBell />}>
          {t("notify.noChannels")}
        </Alert>
      )}
      {sysLang && (
        <Card withBorder>
          <Group justify="space-between" align="center">
            <div>
              <Text fw={600}>{t("notify.systemLanguage")}</Text>
              <Text size="sm" c="dimmed" maw={720}>
                {t("notify.systemLanguageHelp")}
              </Text>
            </div>
            <SegmentedControl
              value={sysLang.language}
              disabled={!sysLang.editable || !can("users", "write")}
              data={sysLang.supported.map((l) => ({ value: l, label: languages[l] ?? l }))}
              onChange={(v) => void changeSysLang(v)}
            />
          </Group>
        </Card>
      )}

      {channels.map((c) => (
        <Card withBorder key={c.id}>
          <Group justify="space-between" align="flex-start">
            <Stack gap={4}>
              <Group gap="xs">
                <Text fw={600}>{c.name}</Text>
                <Badge variant="light">{kindLabels[c.kind] ?? c.kind}</Badge>
                {c.signed && (
                  <Tooltip label={t("notify.signedTip")}>
                    <Badge variant="light" color="teal" leftSection={<IconSignature size={12} />}>
                      {t("notify.signed")}
                    </Badge>
                  </Tooltip>
                )}
                <Text size="xs" c="dimmed" ff="monospace">
                  {c.url_hint}
                </Text>
              </Group>
              <Group gap="lg">
                {allEvents.map((ev) => (
                  <Checkbox
                    key={ev}
                    label={notifyEventLabels[ev]}
                    checked={c.events.includes(ev)}
                    onChange={(e) => {
                      const on = e.currentTarget.checked;
                      const events = on ? [...c.events, ev] : c.events.filter((x) => x !== ev);
                      void update(c, { events }, t("notify.optOut", { event: notifyEventLabels[ev] }));
                    }}
                  />
                ))}
              </Group>
              {c.events.includes("alert") && (
                <AlertFilterEditor
                  value={c.alert_filter ?? {}}
                  rules={ruleOptions}
                  onSave={(f) => void update(c, { alert_filter: f }, t("notify.narrowing"))}
                />
              )}
              <Text size="xs" c={c.last_error && (!c.last_ok_at || c.last_error_at! > c.last_ok_at) ? "red" : "dimmed"}>
                {c.last_ok_at ? t("notify.lastOk", { date: formatDate(c.last_ok_at) }) : t("notify.nothingSent")}
                {c.last_error && c.last_error_at && ` • ${t("notify.lastError", { date: formatDate(c.last_error_at), error: c.last_error })}`}
              </Text>
            </Stack>
            <Group gap="xs">
              <Switch
                label={t("notify.enabled")}
                checked={c.enabled}
                onChange={(e) => void update(c, { enabled: e.currentTarget.checked }, t("notify.disabling"))}
              />
              <Button size="xs" variant="light" leftSection={<IconSend size={14} />} onClick={() => void action(() => notifyApi.test(c.id), t("notify.testSent"))}>
                {t("notify.test")}
              </Button>
              {signable(c.kind) &&
                (c.signed ? (
                  <>
                    <Button size="xs" variant="subtle" leftSection={<IconKey size={14} />} onClick={() => void update(c, { new_secret: true }, t("notify.newSecretLabel"))}>
                      {t("notify.newSecret")}
                    </Button>
                    <Button size="xs" variant="subtle" color="gray" onClick={() => void update(c, { sign: false }, t("notify.unsignLabel"))}>
                      {t("notify.unsign")}
                    </Button>
                  </>
                ) : (
                  <Button size="xs" variant="subtle" leftSection={<IconSignature size={14} />} onClick={() => void update(c, { sign: true }, "")}>
                    {t("notify.sign")}
                  </Button>
                ))}
              <Button
                size="xs"
                variant="subtle"
                color="red"
                leftSection={<IconTrash size={14} />}
                onClick={() =>
                  setPending({
                    label: t("notify.deleting", { name: c.name }),
                    run: async (pw) => {
                      await notifyApi.remove(c.id, pw);
                      load();
                    },
                  })
                }
              >
                {t("notify.delete")}
              </Button>
            </Group>
          </Group>
        </Card>
      ))}

      {log.length > 0 && (
        <Stack gap="xs">
          <Title order={4}>{t("notify.log")}</Title>
          <Table.ScrollContainer minWidth={800}>
            <Table striped verticalSpacing={4}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t("notify.col.time")}</Table.Th>
                  <Table.Th>{t("notify.col.channel")}</Table.Th>
                  <Table.Th>{t("notify.col.kind")}</Table.Th>
                  <Table.Th>{t("notify.col.content")}</Table.Th>
                  <Table.Th>{t("notify.col.result")}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {log.map((l) => (
                  <Table.Tr key={l.id}>
                    <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(l.at)}</Table.Td>
                    <Table.Td>{l.channel}</Table.Td>
                    <Table.Td>{notifyEventLabels[l.event] ?? l.event}</Table.Td>
                    <Table.Td maw={380}>
                      <Text size="sm" lineClamp={1}>
                        {l.title}
                      </Text>
                      {l.anchor_sha256 && (
                        <Tooltip label={l.anchor_sha256} maw={600} multiline>
                          <Text size="xs" ff="monospace" c="dimmed">
                            #{l.anchor_seq} {l.anchor_sha256.slice(0, 16)}…{" "}
                            {l.anchor_match === true && <Badge size="xs" color="green" variant="light">{t("notify.anchorOk")}</Badge>}
                            {l.anchor_match === false && <Badge size="xs" color="red">{t("notify.anchorBad")}</Badge>}
                          </Text>
                        </Tooltip>
                      )}
                    </Table.Td>
                    <Table.Td>
                      {l.ok ? (
                        <Badge color="green" variant="light">{t("notify.sent")}</Badge>
                      ) : (
                        <Tooltip label={l.error} maw={500} multiline>
                          <Badge color="red" variant="light">{t("notify.error")}</Badge>
                        </Tooltip>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Stack>
      )}

      <Modal opened={adding} onClose={() => setAdding(false)} title={t("notify.newTitle")} centered>
        <form onSubmit={add}>
          <Stack gap="sm">
            <SegmentedControl
              value={form.kind}
              onChange={(v) => setForm({ ...form, kind: v as ChannelKind })}
              data={(["discord", "teams", "webhook"] as ChannelKind[]).map((k) => ({ value: k, label: kindLabels[k] }))}
            />
            <TextInput label={t("notify.name")} required value={form.name} onChange={(e) => setForm({ ...form, name: e.currentTarget.value })} />
            <PasswordInput
              label={t("notify.url")}
              description={form.kind === "discord" ? t("notify.urlDiscord") : form.kind === "teams" ? t("notify.urlTeams") : t("notify.urlWebhook")}
              required
              value={form.url}
              onChange={(e) => setForm({ ...form, url: e.currentTarget.value })}
            />
            {signable(form.kind) && (
              <Checkbox
                label={t("notify.signLabel")}
                description={t("notify.signHelp")}
                checked={form.sign}
                onChange={(e) => setForm({ ...form, sign: e.currentTarget.checked })}
              />
            )}
            <Checkbox.Group
              label={t("notify.what")}
              value={form.events}
              onChange={(v) => setForm({ ...form, events: v as NotifyEvent[] })}
            >
              <Stack gap={4} mt={4}>
                {allEvents.map((ev) => (
                  <Checkbox key={ev} value={ev} label={notifyEventLabels[ev]} />
                ))}
              </Stack>
            </Checkbox.Group>
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setAdding(false)}>
                {t("notify.cancel")}
              </Button>
              <Button type="submit" loading={busy}>
                {t("notify.addShort")}
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      <SigningSecret data={secret} onClose={() => setSecret(null)} />
      <Modal opened={!!pending} onClose={() => setPending(null)} title={t("notify.confirmTitle")} centered>
        <form onSubmit={confirm}>
          <Stack gap="sm">
            <Text size="sm">
              {t("notify.confirmText", { what: pending?.label })}
            </Text>
            <ReauthPassword
              label={t("yourPassword")}
              required
              autoFocus
              value={password}
              onChange={setPassword}
            />
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setPending(null)}>
                {t("notify.back")}
              </Button>
              <Button type="submit" color="orange" loading={busy}>
                {t("notify.confirm")}
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Stack>
  );
}
