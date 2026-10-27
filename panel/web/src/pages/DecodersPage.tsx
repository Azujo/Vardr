// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert as MAlert,
  Badge,
  Button,
  Code,
  Group,
  Modal,
  NumberInput,
  ScrollArea,
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
import { IconDownload, IconFileCode, IconFlask, IconHistory, IconPlus, IconWand } from "@tabler/icons-react";
import DecoderWizard from "./DecoderWizard";
import {
  ApiError,
  decodersApi,
  formatDate,
  type DecodeResult,
  type DecoderInfo,
  type DecoderTestResponse,
  type DecoderVersion,
} from "../api";
import { useLocation } from "react-router-dom";
import { useTranslation } from "react-i18next";
import i18n, { serverText } from "../i18n";
import { useAuth } from "../auth";
import { lineDiff } from "../diff";
import { ReauthPassword } from "../sso";

const newDecoderTemplate = () => `id: ${i18n.t("decoders:template.id")}
title: ${i18n.t("decoders:template.title")}
description: |
  ${i18n.t("decoders:template.description")}
version: 1
priority: 60
dataset: ${i18n.t("decoders:template.dataset")}
match:
  # ${i18n.t("decoders:template.matchComment")}
  app: [sshd]
  # peer: [192.168.88.0/24]
  # host: [nas01]
  # regex: 'failed'
parser:
  type: regex   # kv | json | csv | regex | none
  patterns:
    - regex: 'Failed password for (?:invalid user )?(?P<user>\\S+) from (?P<src_ip>[0-9a-fA-F.:]+)'
      set: {event.action: login, event.outcome: failure}
    - regex: 'Accepted \\S+ for (?P<user>\\S+) from (?P<src_ip>[0-9a-fA-F.:]+)'
      set: {event.action: login, event.outcome: success}
fields:
  user.name: user
  source.ip: src_ip
samples:
  - '<38>Oct  9 13:00:00 nas01 sshd[812]: Failed password for root from 203.0.113.9 port 51234 ssh2'
`;


const keyEventFields = ["event.action", "event.outcome", "user.name", "source.ip", "host.name"];

function ResultRow({ r, candidate }: { r: DecodeResult; candidate?: string }) {
  const { t } = useTranslation("decoders");
  const [open, setOpen] = useState(false);
  const color = r.error ? "red" : r.dataset === "syslog.generic" ? "gray" : r.decoder === candidate ? "green" : "blue";
  return (
    <>
      <Table.Tr style={{ cursor: "pointer" }} onClick={() => setOpen((o) => !o)}>
        <Table.Td>
          <Badge color={color} variant={r.decoder === candidate ? "filled" : "light"}>
            {r.error ? t("result.quarantine") : r.decoder || t("result.none")}
          </Badge>
          {r.decoder && !r.pattern && !r.error && (
            <Tooltip label={t("result.noPatternTip")}>
              <Badge color="orange" variant="outline" ml={4}>
                {t("result.noPattern")}
              </Badge>
            </Tooltip>
          )}
          {candidate && r.candidate && r.decoder !== candidate && (
            <Tooltip label={t("result.shadowedTip")}>
              <Badge color="yellow" variant="outline" ml={4}>
                {t("result.shadowed")}
              </Badge>
            </Tooltip>
          )}
        </Table.Td>
        <Table.Td>
          <Text size="xs">{r.dataset}</Text>
        </Table.Td>
        <Table.Td>
          <Group gap={4}>
            {keyEventFields
              .filter((k) => r.event[k])
              .map((k) => (
                <Badge key={k} size="xs" variant="outline" tt="none">
                  {k}: {r.event[k]}
                </Badge>
              ))}
          </Group>
          <Text size="xs" c="dimmed" ff="monospace" lineClamp={open ? undefined : 1} style={{ wordBreak: "break-all" }}>
            {r.raw}
          </Text>
        </Table.Td>
      </Table.Tr>
      {open && (
        <Table.Tr>
          <Table.Td colSpan={3}>
            {r.error && (
              <MAlert color="red" mb="xs">
                {serverText(r.error, r.error_en)}
              </MAlert>
            )}
            <SimpleGrid cols={{ base: 1, md: 3 }} spacing="xs">
              <div>
                <Text size="xs" fw={600}>
                  {t("result.header", { format: r.header.format })}
                </Text>
                <Code block fz="xs">
                  {[
                    r.header.time && `${t("result.time")}: ${formatDate(r.header.time)}`,
                    r.header.host && `host: ${r.header.host}`,
                    r.header.app && `${t("result.program")}: ${r.header.app}${r.header.pid ? `[${r.header.pid}]` : ""}`,
                    r.header.severity && `${t("result.severity")}: ${r.header.severity} (facility ${r.header.facility})`,
                    `${t("result.message")}: ${r.header.message}`,
                  ]
                    .filter(Boolean)
                    .join("\n")}
                </Code>
              </div>
              <div>
                <Text size="xs" fw={600}>
                  {t("result.event")}
                </Text>
                <Code block fz="xs">
                  {Object.entries(r.event)
                    .sort()
                    .map(([k, v]) => `${k}: ${v}`)
                    .join("\n")}
                </Code>
              </div>
              <div>
                <Text size="xs" fw={600}>
                  {t("result.fields", { count: Object.keys(r.fields).length })}
                </Text>
                <ScrollArea.Autosize mah={240}>
                  <Code block fz="xs">
                    {Object.entries(r.fields)
                      .sort()
                      .map(([k, v]) => `${k}: ${v}`)
                      .join("\n") || "—"}
                  </Code>
                </ScrollArea.Autosize>
              </div>
            </SimpleGrid>
          </Table.Td>
        </Table.Tr>
      )}
    </>
  );
}

// Edytor: definicja YAML, próbki (wklejone albo z bazy), test na zestawie
// działających dekoderów z tym na swoim miejscu, zapis (administrator).
function DecoderEditor({
  decoder,
  admin,
  samplesAvailable,
  onSaved,
  initialSource,
}: {
  decoder: DecoderInfo | null;
  admin: boolean;
  samplesAvailable: boolean;
  onSaved: () => void;
  initialSource?: string;
}) {
  const { t } = useTranslation("decoders");
  const [source, setSource] = useState(() => decoder?.source ?? initialSource ?? newDecoderTemplate());
  const [samples, setSamples] = useState("");
  const [peer, setPeer] = useState("");
  const [hours, setHours] = useState<number | string>(24);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [res, setRes] = useState<DecoderTestResponse | null>(null);
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);

  const run = async () => {
    setBusy(true);
    try {
      const lines = samples.split("\n").filter((l) => l.trim() !== "");
      setRes(await decodersApi.test(source, lines, peer.trim()));
    } catch (e) {
      setRes({ ok: false, error: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  const load = async (own: boolean) => {
    setLoading(true);
    try {
      const r = await decodersApi.samples({ decoder: own ? decoder?.id : undefined, peer: peer.trim(), hours: Number(hours) || 24 });
      if (r.samples.length === 0) notifications.show({ color: "gray", message: t("editor.noMessages") });
      setSamples(r.samples.map((s) => s.raw).join("\n"));
      // Test używa jednego adresu nadawcy: próbki od jednego urządzenia – jego adres (warunek peer).
      const peers = new Set(r.samples.map((s) => s.peer));
      if (!peer.trim() && peers.size === 1) setPeer([...peers][0]);
      else if (!peer.trim() && peers.size > 1)
        notifications.show({ color: "yellow", message: t("editor.manyPeers") });
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setLoading(false);
    }
  };

  const save = async () => {
    const id = /^id:\s*(\S+)/m.exec(source)?.[1] ?? "";
    if (!id) {
      notifications.show({ color: "red", message: t("editor.noId") });
      return;
    }
    if (decoder && id !== decoder.id) {
      notifications.show({ color: "red", message: t("editor.idMismatch", { id, current: decoder.id }) });
      return;
    }
    setSaving(true);
    try {
      const r = await decodersApi.save(id, source, note.trim());
      notifications.show({ color: "green", message: t("saved", { revision: r.revision, status: t(`delivery.${r.delivery}`, { defaultValue: r.message }) }) });
      setNote("");
      onSaved();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setSaving(false);
    }
  };

  const s = res?.summary;
  return (
    <Stack gap="xs">
      <Text size="xs" c="dimmed">
        {t("editor.intro")}
      </Text>
      <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="xs">
        <Textarea
          label={t("editor.definition")}
          autosize
          minRows={16}
          maxRows={30}
          spellCheck={false}
          styles={{ input: { fontFamily: "monospace", fontSize: 12 } }}
          value={source}
          onChange={(e) => setSource(e.currentTarget.value)}
        />
        <Stack gap="xs">
          <Textarea
            label={t("editor.samples")}
            autosize
            minRows={8}
            maxRows={16}
            spellCheck={false}
            styles={{ input: { fontFamily: "monospace", fontSize: 12 } }}
            value={samples}
            onChange={(e) => setSamples(e.currentTarget.value)}
            placeholder="<134>Oct  9 20:54:19 MikroTik user admin logged in from 192.168.88.10 via winbox"
          />
          <Group gap="xs" align="flex-end">
            <TextInput
              label={t("editor.peer")}
              description={t("editor.peerHint")}
              placeholder="192.168.88.1"
              w={160}
              value={peer}
              onChange={(e) => setPeer(e.currentTarget.value)}
            />
            {samplesAvailable && (
              <>
                <NumberInput label={t("editor.hours")} w={130} min={1} max={168} value={hours} onChange={setHours} />
                <Button variant="default" leftSection={<IconDownload size={14} />} loading={loading} onClick={() => void load(false)}>
                  {t("editor.unrecognized")}
                </Button>
                {decoder && (
                  <Button variant="default" leftSection={<IconDownload size={14} />} loading={loading} onClick={() => void load(true)}>
                    {t("editor.handled")}
                  </Button>
                )}
              </>
            )}
          </Group>
          <Group>
            <Button leftSection={<IconFlask size={16} />} loading={busy} onClick={() => void run()}>
              {t("editor.test")}
            </Button>
          </Group>
          {admin && (
            <Group align="flex-end" gap="xs">
              <TextInput
                label={t("editor.note")}
                placeholder={t("editor.notePlaceholder")}
                style={{ flex: 1 }}
                value={note}
                onChange={(e) => setNote(e.currentTarget.value)}
              />
              <Button color="green" loading={saving} onClick={() => void save()}>
                {t("saveDeploy")}
              </Button>
            </Group>
          )}
        </Stack>
      </SimpleGrid>
      {res && !res.ok && <MAlert color="red">{serverText(res.error ?? "", res.error_en)}</MAlert>}
      {res?.ok && s && (
        <Stack gap="xs">
          <Group gap="xs">
            <Text size="sm">{t("sum.total", { n: s.total })}</Text>
            {res.decoder && <Badge color="green">{t("sum.this", { n: s.candidate })}</Badge>}
            <Badge color="blue">{t("sum.other", { n: s.other })}</Badge>
            <Badge color="gray">{t("sum.generic", { n: s.generic })}</Badge>
            {s.errors > 0 && <Badge color="red">{t("sum.quarantine", { n: s.errors })}</Badge>}
            {s.no_pattern > 0 && <Badge color="orange">{t("sum.noPattern", { n: s.no_pattern })}</Badge>}
          </Group>
          <Table.ScrollContainer minWidth={760}>
            <Table verticalSpacing={4}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th w={220}>{t("col.decoder")}</Table.Th>
                  <Table.Th w={160}>{t("col.dataset")}</Table.Th>
                  <Table.Th>{t("editor.resultCol")}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {res.results?.map((r, i) => <ResultRow key={i} r={r} candidate={res.decoder?.id} />)}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Stack>
      )}
    </Stack>
  );
}

function Versions({ id }: { id: string }) {
  const { t } = useTranslation("decoders");
  const [versions, setVersions] = useState<DecoderVersion[]>([]);
  const [sel, setSel] = useState<number | null>(null);
  useEffect(() => {
    decodersApi
      .versions(id)
      .then((r) => {
        setVersions(r.versions);
        setSel(r.versions[0]?.id ?? null);
      })
      .catch(() => setVersions([]));
  }, [id]);
  const idx = versions.findIndex((v) => v.id === sel);
  const cur = versions[idx];
  const prev = versions.slice(idx + 1).find((v) => v.source !== "");
  const diff = useMemo(() => (cur && prev && cur.source ? lineDiff(prev.source, cur.source) : null), [cur, prev]);
  if (versions.length === 0) return <Text size="sm">{t("versions.none")}</Text>;
  return (
    <Stack gap="xs">
      <Group gap="xs">
        {versions.map((v) => (
          <Badge key={v.id} variant={v.id === sel ? "filled" : "light"} style={{ cursor: "pointer" }} onClick={() => setSel(v.id)}>
            r{v.revision} · {formatDate(v.changed_at)}
          </Badge>
        ))}
      </Group>
      {cur && (
        <Text size="xs" c="dimmed">
          r{cur.revision}: {t(`versions.action.${cur.action}`)} – {cur.changed_by}, {formatDate(cur.changed_at)}
          {cur.note ? ` · „${cur.note}”` : ""}
        </Text>
      )}
      {cur?.source && (
        <ScrollArea.Autosize mah={460}>
          {diff ? (
            <Code block fz="xs">
              {diff.map((d, i) => (
                <div
                  key={i}
                  style={{ background: d.op === "+" ? "rgba(47,158,68,.15)" : d.op === "-" ? "rgba(224,49,49,.15)" : undefined }}
                >
                  {d.op} {d.line}
                </div>
              ))}
            </Code>
          ) : (
            <Code block>{cur.source}</Code>
          )}
        </ScrollArea.Autosize>
      )}
    </Stack>
  );
}

export default function DecodersPage() {
  const { t } = useTranslation("decoders");
  const { can } = useAuth();
  const admin = can("decoders", "write");
  const canTest = can("decoders", "test");
  const [list, setList] = useState<DecoderInfo[]>([]);
  const [delivery, setDelivery] = useState(true);
  const [samplesOn, setSamplesOn] = useState(false);
  const [error, setError] = useState("");
  const [show, setShow] = useState<DecoderInfo | null>(null);
  const [creating, setCreating] = useState(false);
  const [wizard, setWizard] = useState(false);
  const [draft, setDraft] = useState<string | undefined>(undefined);
  // Definicja z kreatora otwartego w kwarantannie – do dopracowania w edytorze.
  const location = useLocation();
  useEffect(() => {
    const d = (location.state as { draft?: string } | null)?.draft;
    if (d) {
      setDraft(d);
      setCreating(true);
      window.history.replaceState({}, "");
    }
  }, [location.state]);
  const [tab, setTab] = useState<string | null>("source");
  const [action, setAction] = useState<{ d: DecoderInfo; kind: "disable" | "enable" | "revert" } | null>(null);
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const [needPassword, setNeedPassword] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    decodersApi
      .list()
      .then((r) => {
        const sorted = [...r.decoders].sort((a, b) => (a.order || 999) - (b.order || 999) || a.id.localeCompare(b.id));
        setList(sorted);
        setDelivery(r.delivery);
        setSamplesOn(r.samples);
        setShow((s) => (s ? (sorted.find((d) => d.id === s.id) ?? null) : s));
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);
  useEffect(() => load(), [load]);

  const weakening = action?.kind === "disable" || (action?.kind === "revert" && action.d.origin === "custom");
  const apply = async () => {
    if (!action) return;
    setBusy(true);
    try {
      const r =
        action.kind === "revert"
          ? await decodersApi.revert(action.d.id, reason, password)
          : await decodersApi.setEnabled(action.d.id, action.kind === "enable", reason, password);
      notifications.show({ color: "green", message: t(`delivery.${r.delivery}`, { defaultValue: r.message }) });
      if (action.kind === "revert" && action.d.origin === "custom") setShow(null);
      setAction(null);
      setReason("");
      setPassword("");
      setNeedPassword(false);
      load();
    } catch (e) {
      if (e instanceof ApiError && e.code === "reauth_required") setNeedPassword(true);
      else notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack>
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>{t("title")}</Title>
          <Text c="dimmed" size="sm" maw={860}>
            {t("intro")}
          </Text>
        </div>
        {canTest && (
          <Group gap="xs" wrap="nowrap">
          <Button variant="light" leftSection={<IconWand size={16} />} onClick={() => setWizard(true)}>
            {t("wizardButton")}
          </Button>
          <Button
            leftSection={<IconPlus size={16} />}
            onClick={() => {
              setDraft(undefined);
              setCreating(true);
            }}
          >
            {t("new")}
          </Button>
          </Group>
        )}
      </Group>
      {error && <MAlert color="red">{error}</MAlert>}
      {!delivery && (
        <MAlert color="orange">
          {t("noNats")}
        </MAlert>
      )}
      <Table.ScrollContainer minWidth={900}>
        <Table striped highlightOnHover verticalSpacing="xs">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t("col.enabled")}</Table.Th>
              <Table.Th>{t("col.order")}</Table.Th>
              <Table.Th>{t("col.decoder")}</Table.Th>
              <Table.Th>{t("col.dataset")}</Table.Th>
              <Table.Th>{t("col.priority")}</Table.Th>
              <Table.Th>{t("col.changes")}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {list.map((d) => (
              <Table.Tr
                key={d.id}
                style={{ cursor: "pointer", opacity: d.enabled ? 1 : 0.55 }}
                onClick={() => {
                  setShow(d);
                  setTab("source");
                }}
              >
                <Table.Td onClick={(e) => e.stopPropagation()}>
                  <Switch
                    size="sm"
                    checked={d.enabled}
                    disabled={!admin}
                    onChange={(e) => setAction({ d, kind: e.currentTarget.checked ? "enable" : "disable" })}
                    aria-label={t("col.enabled")}
                  />
                </Table.Td>
                <Table.Td>{d.order || "—"}</Table.Td>
                <Table.Td maw={440}>
                  <Group gap={6}>
                    <Text size="sm" fw={500}>
                      {d.title}
                    </Text>
                    {d.origin === "builtin" ? (
                      <Badge size="xs" variant="light" color="gray">
                        {t("builtin")}
                      </Badge>
                    ) : (
                      <Badge size="xs" variant="light" color="grape">
                        {t("custom")}
                      </Badge>
                    )}
                    {d.modified && (
                      <Badge size="xs" variant="outline" color="grape">
                        {t("modified")}
                      </Badge>
                    )}
                    {d.error && (
                      <Tooltip label={serverText(d.error, d.error_en)} multiline w={360}>
                        <Badge size="xs" color="red">
                          {t("error")}
                        </Badge>
                      </Tooltip>
                    )}
                  </Group>
                  <Text size="xs" c="dimmed" ff="monospace">
                    {d.id} · v{d.version} · {t("samplesCount", { n: d.samples })}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Code>{d.dataset}</Code>
                </Table.Td>
                <Table.Td>{d.priority}</Table.Td>
                <Table.Td>
                  {d.updated_by ? (
                    <Text size="xs">
                      r{d.revision} · {d.updated_by}, {formatDate(d.updated_at)}
                    </Text>
                  ) : (
                    <Text size="xs" c="dimmed">
                      —
                    </Text>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={!!show} onClose={() => setShow(null)} title={show?.title} size="90%">
        {show && (
          <Stack gap="xs">
            <Group justify="space-between">
              <Text size="xs" c="dimmed">
                {show.id} · {show.dataset} · {t("priorityN", { n: show.priority })}
                {show.revision ? ` · ${t("revisionInfo", { n: show.revision, by: show.updated_by, date: formatDate(show.updated_at) })}` : ""}
              </Text>
              {admin && (show.modified || show.origin === "custom") && (
                <Button size="xs" variant="subtle" color="red" onClick={() => setAction({ d: show, kind: "revert" })}>
                  {show.origin === "custom" ? t("action.delete") : t("action.restoreBuiltin")}
                </Button>
              )}
            </Group>
            {show.description && (
              <Text size="sm" style={{ whiteSpace: "pre-line" }}>
                {show.description}
              </Text>
            )}
            <Tabs value={tab} onChange={setTab}>
              <Tabs.List>
                <Tabs.Tab value="source" leftSection={<IconFileCode size={14} />}>
                  {t("tab.source")}
                </Tabs.Tab>
                {canTest && (
                  <Tabs.Tab value="edit" leftSection={<IconFlask size={14} />}>
                    {admin ? t("tab.edit") : t("tab.test")}
                  </Tabs.Tab>
                )}
                <Tabs.Tab value="versions" leftSection={<IconHistory size={14} />}>
                  {t("tab.history")}
                </Tabs.Tab>
                {show.builtin_source && <Tabs.Tab value="builtin">{t("tab.builtin")}</Tabs.Tab>}
              </Tabs.List>
              <Tabs.Panel value="source" pt="xs">
                <ScrollArea.Autosize mah={560}>
                  <Code block>{show.source}</Code>
                </ScrollArea.Autosize>
              </Tabs.Panel>
              <Tabs.Panel value="edit" pt="xs">
                {tab === "edit" && <DecoderEditor decoder={show} admin={admin} samplesAvailable={samplesOn} onSaved={load} />}
              </Tabs.Panel>
              <Tabs.Panel value="versions" pt="xs">
                {tab === "versions" && <Versions id={show.id} />}
              </Tabs.Panel>
              <Tabs.Panel value="builtin" pt="xs">
                {show.builtin_source && (
                  <ScrollArea.Autosize mah={560}>
                    <Code block fz="xs">
                      {lineDiff(show.builtin_source, show.source).map((d, i) => (
                        <div
                          key={i}
                          style={{ background: d.op === "+" ? "rgba(47,158,68,.15)" : d.op === "-" ? "rgba(224,49,49,.15)" : undefined }}
                        >
                          {d.op} {d.line}
                        </div>
                      ))}
                    </Code>
                  </ScrollArea.Autosize>
                )}
              </Tabs.Panel>
            </Tabs>
          </Stack>
        )}
      </Modal>

      <Modal opened={creating} onClose={() => setCreating(false)} title={t("new")} size="90%">
        {creating && (
          <DecoderEditor
            decoder={null}
            admin={admin}
            samplesAvailable={samplesOn}
            initialSource={draft}
            onSaved={() => {
              setCreating(false);
              load();
            }}
          />
        )}
      </Modal>

      <Modal opened={wizard} onClose={() => setWizard(false)} title={t("wizardTitle")} size="95%">
        {wizard && (
          <DecoderWizard
            initialSamples={[]}
            admin={admin}
            samplesAvailable={samplesOn}
            onEdit={(yaml) => {
              setDraft(yaml);
              setWizard(false);
              setCreating(true);
            }}
            onSaved={() => {
              setWizard(false);
              load();
            }}
          />
        )}
      </Modal>

      <Modal
        opened={!!action}
        onClose={() => {
          setAction(null);
          setNeedPassword(false);
        }}
        title={
          action
            ? t(
                action.kind === "revert"
                  ? action.d.origin === "custom"
                    ? "action.titleDelete"
                    : "action.titleRestore"
                  : action.kind === "disable"
                    ? "action.titleDisable"
                    : "action.titleEnable",
                { title: action.d.title },
              )
            : ""
        }
        centered
      >
        {action && (
          <Stack>
            {weakening && (
              <MAlert color="orange">
                {t("action.warning.0")}
                <Code>{action.d.dataset}</Code>
                {t("action.warning.1")}
              </MAlert>
            )}
            {action.kind === "revert" && action.d.origin === "builtin" && (
              <Text size="sm">{t("action.restoreInfo")}</Text>
            )}
            <Textarea
              label={t("action.reason")}
              description={weakening ? t("action.reasonHint") : t("action.optional")}
              autosize
              minRows={2}
              value={reason}
              onChange={(e) => setReason(e.currentTarget.value)}
            />
            {(needPassword || weakening) && (
              <ReauthPassword label={t("action.password")} value={password} onChange={setPassword} />
            )}
            <Group justify="flex-end">
              <Button
                color={weakening ? "red" : undefined}
                loading={busy}
                disabled={weakening && (reason.trim().length < 3 || !password)}
                onClick={() => void apply()}
              >
                {action.kind === "revert"
                  ? action.d.origin === "custom"
                    ? t("action.delete")
                    : t("action.restore")
                  : action.kind === "disable"
                    ? t("action.disable")
                    : t("action.enable")}
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
