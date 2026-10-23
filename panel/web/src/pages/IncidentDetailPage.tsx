// SPDX-License-Identifier: AGPL-3.0-or-later

// Incydent: obsługa (status, waga, prowadzący), ustalenia, alerty, oś czasu,
// a dla incydentu poważnego (NIS2) – terminy i zgłoszenia do CSIRT.
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert,
  Anchor,
  Badge,
  Button,
  Card,
  Code,
  CopyButton,
  Grid,
  Group,
  Modal,
  Select,
  Stack,
  Stepper,
  Switch,
  Table,
  Tabs,
  Text,
  TextInput,
  Textarea,
  Timeline,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconArrowLeft,
  IconCheck,
  IconCopy,
  IconDownload,
  IconFileCertificate,
  IconLock,
  IconSend,
  IconTrash,
} from "@tabler/icons-react";
import { Link, useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import {
  alertsApi,
  exportsApi,
  formatDate,
  incidentSeverityColors,
  incidentsApi,
  levelLabels,
  reportKinds,
  ruleText,
  settingsApi,
  type Incident,
  type IncidentActivity,
  type IncidentAlert,
  type IncidentDeadline,
  type IncidentReport,
  type IncidentStatus,
  type ReportKind,
  type RuleInfo,
  type TriState,
} from "../api";
import { useAuth } from "../auth";
import { languages, locale } from "../i18n";
import { DeadlineBadge } from "../incidents";

const triStates: TriState[] = ["yes", "no", "unknown"];
// Pola z długim tekstem – w osi czasu tylko informacja o zmianie.
const longFields = ["description", "impact", "root_cause", "mitigation", "iocs"];

// Ścieżka statusów i dozwolone przejścia (jak na serwerze): praca może
// wracać, zamknięcie jest ostateczne. label – klucz action.* w tłumaczeniach.
const statusPath: IncidentStatus[] = ["open", "investigating", "contained", "resolved", "closed"];
const transitions: Record<IncidentStatus, { to: IncidentStatus; label: string; color?: string; variant?: string }[]> = {
  open: [
    { to: "investigating", label: "investigate" },
    { to: "contained", label: "contain", variant: "light" },
    { to: "resolved", label: "resolve", variant: "light" },
  ],
  investigating: [
    { to: "contained", label: "contain" },
    { to: "resolved", label: "resolve", variant: "light" },
    { to: "open", label: "reopen", variant: "subtle" },
  ],
  contained: [
    { to: "resolved", label: "resolve" },
    { to: "investigating", label: "backToInvestigating", variant: "subtle" },
  ],
  resolved: [
    { to: "closed", label: "close", color: "gray" },
    { to: "contained", label: "backToContained", variant: "subtle" },
    { to: "investigating", label: "backToInvestigating", variant: "subtle" },
  ],
  closed: [],
};

// datetime-local ↔ ISO (czas lokalny przeglądarki).
function toLocalInput(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

type T = TFunction<"incidents">;

// Wartość pola z wpisu osi czasu (serwer zapisuje kody) w języku czytającego.
function fieldValue(t: T, field: string, v: unknown): string {
  const s = String(v ?? "");
  if (!s) return "—";
  switch (field) {
    case "severity":
      return t(`severity.${s}`, { defaultValue: s });
    case "status":
      return t(`status.${s}`, { defaultValue: s });
    case "malicious":
    case "cross_border":
      return t(`tri.${s}`, { defaultValue: s });
    case "significant":
      return s === "true" ? t("tri.yes") : s === "false" ? t("tri.no") : s;
    case "aware_at":
      return formatDate(s);
    default:
      return s;
  }
}

// Wpis osi czasu składany z kodu i szczegółów, żeby każdy czytał go w swoim
// języku; a.text (po polsku) – gdy wpis nie ma szczegółów (starsze wpisy).
function activityText(t: T, a: IncidentActivity): string {
  const d = a.details ?? {};
  switch (a.kind) {
    case "created":
      return t("activity.created", { count: Number(d.alerts ?? 0) });
    case "field": {
      const f = String(d.field ?? a.text);
      const name = t(`field.${f}`, { defaultValue: f });
      return longFields.includes(f)
        ? t("activity.changed", { field: name })
        : t("activity.fieldChange", { field: name, from: fieldValue(t, f, d.from), to: fieldValue(t, f, d.to) });
    }
    case "alerts_added":
      return Array.isArray(d.alert_ids) ? t("activity.alertsAdded", { count: d.alert_ids.length }) : a.text;
    case "alert_removed":
      return d.alert_id ? t("activity.alertRemoved", { id: d.alert_id }) : a.text;
    case "report_submitted": {
      const text = t("activity.reportSubmitted", { kind: t(`report.${String(d.kind ?? a.text)}`, { defaultValue: a.text }) });
      return d.reference ? t("activity.reportReference", { text, reference: String(d.reference) }) : text;
    }
    case "evidence":
      return d.export_id
        ? t("activity.evidence", {
            id: d.export_id,
            from: formatDate(String(d.from)),
            to: formatDate(String(d.to)),
            agents: Number(d.agents) || t("activity.agentsAll"),
          })
        : a.text;
    default:
      return a.text;
  }
}

function ReportEditor({
  id,
  kind,
  report,
  canEdit,
  onChanged,
}: {
  id: number;
  kind: ReportKind;
  report?: IncidentReport;
  canEdit: boolean;
  onChanged: () => void;
}) {
  const { t } = useTranslation("incidents");
  const [content, setContent] = useState(report?.content ?? "");
  const [busy, setBusy] = useState(false);
  // Język szkicu: domyślnie język systemu (ustawienie w Powiadomieniach).
  const [draftLang, setDraftLang] = useState<string | null>(null);
  useEffect(() => {
    settingsApi
      .language()
      .then((r) => setDraftLang((cur) => cur ?? r.language))
      .catch(() => undefined);
  }, []);
  const [submitOpen, setSubmitOpen] = useState(false);
  const [reference, setReference] = useState("");
  const [sentAt, setSentAt] = useState(toLocalInput(new Date().toISOString()));
  const submitted = !!report?.submitted_at;
  useEffect(() => setContent(report?.content ?? ""), [report?.content]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };
  const download = () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }));
    a.download = t("report_editor.fileName", { id, kind });
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <Stack gap="xs">
      {submitted ? (
        <Alert color="green" icon={<IconCheck size={16} />}>
          {t("report_editor.submitted", {
            date: formatDate(report!.submitted_at),
            by: report!.submitted_by,
            reference: report!.reference ? t("report_editor.submittedReference", { reference: report!.reference }) : "",
          })}
        </Alert>
      ) : (
        <Text size="xs" c="dimmed">
          {t("report_editor.hint")} {t("report_editor.draftLanguage")}
        </Text>
      )}
      <Textarea
        autosize
        minRows={10}
        maxRows={30}
        styles={{ input: { fontFamily: "monospace", fontSize: 12 } }}
        value={content}
        readOnly={submitted || !canEdit}
        onChange={(e) => setContent(e.currentTarget.value)}
        placeholder={t("report_editor.placeholder")}
      />
      <Group gap="xs">
        {!submitted && canEdit && (
          <>
            <Button
              size="xs"
              variant="light"
              loading={busy}
              onClick={() =>
                void run(async () => {
                  if (content.trim() && !window.confirm(t("report_editor.replaceConfirm"))) return;
                  setContent((await incidentsApi.draft(id, kind, draftLang ?? undefined)).content);
                })
              }
            >
              {t("report_editor.draft")}
            </Button>
            <Select
              size="xs"
              w={130}
              aria-label={t("report_editor.draftLanguageLabel")}
              title={t("report_editor.draftLanguageLabel")}
              data={Object.entries(languages).map(([value, label]) => ({ value, label }))}
              value={draftLang}
              onChange={setDraftLang}
              allowDeselect={false}
            />
            <Button
              size="xs"
              variant="light"
              loading={busy}
              disabled={!content.trim()}
              onClick={() =>
                void run(async () => {
                  await incidentsApi.saveReport(id, kind, content);
                  notifications.show({ color: "green", message: t("report_editor.saved") });
                  onChanged();
                })
              }
            >
              {t("report_editor.save")}
            </Button>
            <Button size="xs" color="green" leftSection={<IconSend size={14} />} disabled={!content.trim()} onClick={() => setSubmitOpen(true)}>
              {t("report_editor.markSent")}
            </Button>
          </>
        )}
        <CopyButton value={content}>
          {({ copied, copy }) => (
            <Button size="xs" variant="subtle" leftSection={copied ? <IconCheck size={14} /> : <IconCopy size={14} />} onClick={copy} disabled={!content}>
              {copied ? t("report_editor.copied") : t("report_editor.copy")}
            </Button>
          )}
        </CopyButton>
        <Button size="xs" variant="subtle" leftSection={<IconDownload size={14} />} onClick={download} disabled={!content}>
          {t("report_editor.download")}
        </Button>
      </Group>
      <Modal opened={submitOpen} onClose={() => setSubmitOpen(false)} title={t("report_editor.submitTitle", { kind: t(`report.${kind}`) })} centered>
        <Stack>
          <Text size="sm">{t("report_editor.submitInfo")}</Text>
          <TextInput label={t("report_editor.sentAt")} type="datetime-local" value={sentAt} onChange={(e) => setSentAt(e.currentTarget.value)} />
          <TextInput
            label={t("report_editor.reference")}
            placeholder={t("report_editor.optional")}
            value={reference}
            onChange={(e) => setReference(e.currentTarget.value)}
          />
          <Button
            color="green"
            loading={busy}
            onClick={() =>
              void run(async () => {
                await incidentsApi.submitReport(id, kind, content, reference, sentAt ? new Date(sentAt).toISOString() : undefined);
                setSubmitOpen(false);
                onChanged();
              })
            }
          >
            {t("report_editor.markSent")}
          </Button>
        </Stack>
      </Modal>
    </Stack>
  );
}

export default function IncidentDetailPage() {
  const { id: idParam } = useParams();
  const id = Number(idParam);
  const { t } = useTranslation("incidents");
  const { can } = useAuth();
  const [x, setX] = useState<Incident | null>(null);
  // Zamknięty incydent – tylko do odczytu (serwer też odrzuca zmiany).
  const canEdit = can("incidents", "write") && x?.status !== "closed";
  const [closeOpen, setCloseOpen] = useState(false);
  const [summary, setSummary] = useState("");
  const [alerts, setAlerts] = useState<IncidentAlert[]>([]);
  const [activity, setActivity] = useState<IncidentActivity[]>([]);
  const [reports, setReports] = useState<IncidentReport[]>([]);
  const [deadlines, setDeadlines] = useState<IncidentDeadline[]>([]);
  const [now, setNow] = useState(Date.now());
  const [error, setError] = useState("");
  const [assignees, setAssignees] = useState<{ username: string; display_name: string }[]>([]);
  const [findings, setFindings] = useState({ description: "", impact: "", root_cause: "", mitigation: "", iocs: "" });
  const [note, setNote] = useState("");
  const [tab, setTab] = useState<string | null>("early_warning");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    incidentsApi
      .get(id)
      .then((r) => {
        setX(r.incident);
        setAlerts(r.alerts);
        setActivity(r.activity);
        setReports(r.reports);
        setDeadlines(r.deadlines);
        setNow(new Date(r.now).getTime());
        setFindings({
          description: r.incident.description,
          impact: r.incident.impact,
          root_cause: r.incident.root_cause,
          mitigation: r.incident.mitigation,
          iocs: r.incident.iocs,
        });
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [id]);
  useEffect(load, [load]);
  useEffect(() => {
    if (canEdit)
      alertsApi
        .assignees()
        .then((r) => setAssignees(r.assignees))
        .catch(() => setAssignees([]));
  }, [canEdit]);
  // Alerty incydentu to migawki z polskim tytułem – w innym języku tytuł
  // z tłumaczenia reguły.
  const [rules, setRules] = useState<Record<string, RuleInfo>>({});
  useEffect(() => {
    if (locale() === "pl") return;
    alertsApi
      .rules()
      .then((r) => setRules(Object.fromEntries(r.rules.map((x) => [x.id, x]))))
      .catch(() => setRules({}));
  }, []);
  useEffect(() => {
    const t = setInterval(() => setNow((n) => n + 60000), 60000);
    return () => clearInterval(t);
  }, []);

  const patch = async (p: Partial<Incident> & { comment?: string }) => {
    setBusy(true);
    try {
      await incidentsApi.update(id, p);
      load();
      return true;
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
      return false;
    } finally {
      setBusy(false);
    }
  };

  // Paczka dowodowa: eksport z Urd – pełne godziny od pierwszego do
  // ostatniego alertu (±1 h), tylko agenci z alertów incydentu.
  const evidence = useMemo(() => {
    if (alerts.length === 0) return null;
    const first = Math.min(...alerts.map((a) => new Date(a.first_seen).getTime())) - 3600000;
    const last = Math.max(...alerts.map((a) => new Date(a.last_seen).getTime())) + 3600000;
    const from = new Date(Math.floor(first / 3600000) * 3600000);
    const to = new Date(Math.ceil(last / 3600000) * 3600000);
    const agents = [...new Set(alerts.map((a) => a.agent_id).filter(Boolean))];
    return { from, to, agents, tooLong: to.getTime() - from.getTime() > 31 * 86400000 };
  }, [alerts]);
  const requestEvidence = async () => {
    if (!evidence || !x) return;
    setBusy(true);
    try {
      const r = await exportsApi.create({
        from: evidence.from.toISOString(),
        to: evidence.to.toISOString(),
        reason: t("detail.evidenceReason", { id: x.id, title: x.title }),
        agents: evidence.agents,
      });
      await incidentsApi.evidence(id, {
        text: t("activity.evidence", {
          id: r.export.id,
          from: formatDate(evidence.from.toISOString()),
          to: formatDate(evidence.to.toISOString()),
          agents: evidence.agents.length || t("activity.agentsAll"),
        }),
        export_id: r.export.id,
        from: evidence.from.toISOString(),
        to: evidence.to.toISOString(),
        agents: evidence.agents.length,
      });
      notifications.show({ color: "green", message: t("detail.evidenceDone", { id: r.export.id }) });
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  if (error) return <Alert color="red">{error}</Alert>;
  if (!x) return null;
  const findingsChanged =
    findings.description !== x.description ||
    findings.impact !== x.impact ||
    findings.root_cause !== x.root_cause ||
    findings.mitigation !== x.mitigation ||
    findings.iocs !== x.iocs;
  const repByKind = Object.fromEntries(reports.map((r) => [r.kind, r]));
  const triData = triStates.map((value) => ({ value, label: t(`tri.${value}`) }));

  return (
    <Stack>
      <Anchor component={Link} to="/incidents" size="sm">
        <Group gap={4}>
          <IconArrowLeft size={14} /> {t("detail.back")}
        </Group>
      </Anchor>
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>
            #{x.id} {x.title}
          </Title>
          <Text size="xs" c="dimmed">
            {t("detail.meta", { by: x.created_by, created: formatDate(x.created_at), updated: formatDate(x.updated_at) })}
            {x.closed_at && t("detail.metaClosed", { closed: formatDate(x.closed_at) })}
          </Text>
        </div>
        <Group gap="xs">
          {x.significant && (
            <Badge color="red" size="lg">
              {t("detail.significantBadge")}
            </Badge>
          )}
        </Group>
      </Group>

      {x.status === "closed" && (
        <Alert color="gray" icon={<IconLock size={16} />}>
          {t("detail.closedInfo", { date: formatDate(x.closed_at) })}
        </Alert>
      )}
      <Card withBorder>
        <Stack gap="sm">
          <Stepper active={statusPath.indexOf(x.status)} size="sm" allowNextStepsSelect={false}>
            {statusPath.map((st) => (
              <Stepper.Step key={st} label={t(`status.${st}`)} />
            ))}
          </Stepper>
          {canEdit && (
            <Group gap="xs">
              {transitions[x.status].map((tr) => (
                <Button
                  key={tr.to}
                  size="xs"
                  color={tr.color}
                  variant={tr.variant ?? "filled"}
                  loading={busy}
                  leftSection={tr.to === "closed" ? <IconLock size={14} /> : undefined}
                  onClick={() => {
                    if (tr.to === "closed") {
                      setSummary("");
                      setCloseOpen(true);
                    } else void patch({ status: tr.to });
                  }}
                >
                  {t(`action.${tr.label}`)}
                </Button>
              ))}
            </Group>
          )}
        </Stack>
      </Card>

      <Grid>
        <Grid.Col span={{ base: 12, md: 7 }}>
          <Card withBorder>
            <Stack gap="xs">
              <Group grow>
                <Select
                  label={t("detail.severity")}
                  disabled={!canEdit || busy}
                  value={x.severity}
                  allowDeselect={false}
                  onChange={(v) => v && v !== x.severity && void patch({ severity: v as Incident["severity"] })}
                  data={Object.keys(incidentSeverityColors).map((value) => ({ value, label: t(`severity.${value}`) }))}
                />
                <Select
                  label={t("detail.assignee")}
                  disabled={!canEdit || busy}
                  value={x.assignee || null}
                  clearable
                  onChange={(v) => (v ?? "") !== x.assignee && void patch({ assignee: v ?? "" })}
                  data={[
                    ...assignees.map((a) => ({ value: a.username, label: a.display_name || a.username })),
                    ...(x.assignee && !assignees.some((a) => a.username === x.assignee) ? [{ value: x.assignee, label: x.assignee }] : []),
                  ]}
                />
              </Group>
              <Textarea
                label={t("detail.description")}
                autosize
                minRows={2}
                readOnly={!canEdit}
                value={findings.description}
                onChange={(e) => setFindings({ ...findings, description: e.currentTarget.value })}
              />
              <Textarea
                label={t("detail.impact")}
                autosize
                minRows={2}
                readOnly={!canEdit}
                value={findings.impact}
                onChange={(e) => setFindings({ ...findings, impact: e.currentTarget.value })}
              />
              <Textarea
                label={t("detail.rootCause")}
                autosize
                minRows={2}
                readOnly={!canEdit}
                value={findings.root_cause}
                onChange={(e) => setFindings({ ...findings, root_cause: e.currentTarget.value })}
              />
              <Textarea
                label={t("detail.mitigation")}
                autosize
                minRows={2}
                readOnly={!canEdit}
                value={findings.mitigation}
                onChange={(e) => setFindings({ ...findings, mitigation: e.currentTarget.value })}
              />
              <Textarea
                label={t("detail.iocs")}
                autosize
                minRows={2}
                readOnly={!canEdit}
                styles={{ input: { fontFamily: "monospace", fontSize: 12 } }}
                value={findings.iocs}
                onChange={(e) => setFindings({ ...findings, iocs: e.currentTarget.value })}
              />
              {canEdit && (
                <Group>
                  <Button size="xs" disabled={!findingsChanged} loading={busy} onClick={() => void patch(findings)}>
                    {t("detail.saveFindings")}
                  </Button>
                </Group>
              )}
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 5 }}>
          <Card withBorder>
            <Stack gap="xs">
              <Title order={4}>{t("detail.nis2")}</Title>
              <Switch
                label={t("detail.significant")}
                checked={x.significant}
                disabled={!canEdit || busy}
                onChange={(e) => void patch({ significant: e.currentTarget.checked })}
              />
              <TextInput
                label={t("detail.awareAt")}
                type="datetime-local"
                disabled={!canEdit || busy || !x.significant}
                value={toLocalInput(x.aware_at)}
                onChange={(e) => e.currentTarget.value && void patch({ aware_at: new Date(e.currentTarget.value).toISOString() })}
              />
              <Group grow>
                <Select
                  label={t("detail.malicious")}
                  disabled={!canEdit || busy}
                  value={x.malicious}
                  allowDeselect={false}
                  onChange={(v) => v && v !== x.malicious && void patch({ malicious: v as TriState })}
                  data={triData}
                />
                <Select
                  label={t("detail.crossBorder")}
                  disabled={!canEdit || busy}
                  value={x.cross_border}
                  allowDeselect={false}
                  onChange={(v) => v && v !== x.cross_border && void patch({ cross_border: v as TriState })}
                  data={triData}
                />
              </Group>
              {x.significant ? (
                <Stack gap={4}>
                  {deadlines.map((d) => (
                    <DeadlineBadge key={d.kind} d={d} now={now} />
                  ))}
                </Stack>
              ) : (
                <Text size="xs" c="dimmed">
                  {t("detail.deadlinesHint")}
                </Text>
              )}
              {can("archive", "export") && evidence && (
                <Button
                  size="xs"
                  variant="light"
                  leftSection={<IconFileCertificate size={14} />}
                  loading={busy}
                  disabled={evidence.tooLong}
                  title={evidence.tooLong ? t("detail.evidenceTooLong") : undefined}
                  onClick={() => void requestEvidence()}
                >
                  {t("detail.evidence")}
                </Button>
              )}
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>

      {x.significant && (
        <Card withBorder>
          <Title order={4} mb="xs">
            {t("detail.reports")}
          </Title>
          <Tabs value={tab} onChange={setTab}>
            <Tabs.List>
              {reportKinds.map((k) => (
                <Tabs.Tab key={k} value={k} rightSection={repByKind[k]?.submitted_at ? <IconCheck size={12} color="green" /> : null}>
                  {t(`report.${k}`)}
                </Tabs.Tab>
              ))}
            </Tabs.List>
            {reportKinds.map((k) => (
              <Tabs.Panel key={k} value={k} pt="xs">
                {tab === k && <ReportEditor id={id} kind={k} report={repByKind[k]} canEdit={canEdit} onChanged={load} />}
              </Tabs.Panel>
            ))}
          </Tabs>
        </Card>
      )}

      <Card withBorder>
        <Title order={4} mb="xs">
          {t("detail.alerts", { count: alerts.length })}
        </Title>
        {alerts.length === 0 ? (
          <Text size="sm" c="dimmed">
            {t("detail.noAlerts")}
          </Text>
        ) : (
          <Table.ScrollContainer minWidth={800}>
            <Table verticalSpacing={4}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t("detail.colFirst")}</Table.Th>
                  <Table.Th>{t("detail.colLevel")}</Table.Th>
                  <Table.Th>{t("detail.colRule")}</Table.Th>
                  <Table.Th>{t("detail.colHost")}</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {alerts.map((a) => (
                  <Table.Tr key={a.alert_id}>
                    <Table.Td>
                      <Text size="xs">{formatDate(a.first_seen)}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge size="sm" color={levelLabels[a.level]?.color}>
                        {levelLabels[a.level]?.label ?? a.level}
                      </Badge>
                    </Table.Td>
                    <Table.Td maw={380}>
                      <Anchor component={Link} to={`/alerts/${a.alert_id}`} size="sm">
                        {rules[a.rule_id] ? ruleText(rules[a.rule_id]).title : a.rule_title}
                      </Anchor>
                      <Text size="xs" c="dimmed" lineClamp={1}>
                        {a.summary}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs">
                        {a.host_name || "—"}
                        {a.user_name && ` · ${a.user_name}`}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      {canEdit && (
                        <Button
                          size="compact-xs"
                          variant="subtle"
                          color="red"
                          onClick={() =>
                            window.confirm(t("detail.removeAlert", { id: a.alert_id })) &&
                            void incidentsApi.removeAlert(id, a.alert_id).then(load)
                          }
                        >
                          <IconTrash size={14} />
                        </Button>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Card>

      <Modal opened={closeOpen} onClose={() => setCloseOpen(false)} title={t("detail.closeTitle", { id: x.id })} centered>
        <Stack>
          <Alert color="orange">
            {t("detail.closeWarning")}
            {x.significant && t("detail.closeWarningNis2")}
          </Alert>
          <Textarea
            label={t("detail.summary")}
            description={t("detail.summaryHint")}
            autosize
            minRows={3}
            value={summary}
            onChange={(e) => setSummary(e.currentTarget.value)}
            autoFocus
          />
          <Button
            color="gray"
            leftSection={<IconLock size={16} />}
            loading={busy}
            disabled={summary.trim().length < 10}
            onClick={() =>
              void patch({ status: "closed", comment: summary }).then((ok) => {
                if (ok) setCloseOpen(false);
              })
            }
          >
            {t("action.close")}
          </Button>
        </Stack>
      </Modal>

      <Card withBorder>
        <Title order={4} mb="xs">
          {t("detail.timeline")}
        </Title>
        {canEdit && (
          <Group align="flex-end" mb="sm">
            <Textarea
              style={{ flex: 1 }}
              autosize
              minRows={1}
              placeholder={t("detail.notePlaceholder")}
              value={note}
              onChange={(e) => setNote(e.currentTarget.value)}
            />
            <Button
              disabled={!note.trim()}
              onClick={() =>
                void incidentsApi.note(id, note).then(() => {
                  setNote("");
                  load();
                })
              }
            >
              {t("detail.addNote")}
            </Button>
          </Group>
        )}
        <Timeline bulletSize={12} lineWidth={2}>
          {[...activity].reverse().map((a) => (
            <Timeline.Item
              key={a.id}
              color={a.kind === "note" ? "blue" : a.kind === "report_submitted" ? "green" : a.kind === "evidence" ? "grape" : "gray"}
              title={
                <Text size="xs" c="dimmed">
                  {formatDate(a.at)} · {a.username}
                </Text>
              }
            >
              {a.kind === "note" ? (
                <Code block>{a.text}</Code>
              ) : (
                <Text size="sm">{activityText(t, a)}</Text>
              )}
            </Timeline.Item>
          ))}
        </Timeline>
      </Card>
    </Stack>
  );
}
