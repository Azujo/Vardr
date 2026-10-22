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
import {
  alertsApi,
  exportsApi,
  formatDate,
  incidentSeverityLabels,
  incidentStatusLabels,
  incidentsApi,
  levelLabels,
  reportKindLabels,
  type Incident,
  type IncidentActivity,
  type IncidentAlert,
  type IncidentDeadline,
  type IncidentReport,
  type IncidentStatus,
  type ReportKind,
  type TriState,
} from "../api";
import { useAuth } from "../auth";
import { DeadlineBadge } from "../incidents";

const triLabels: Record<TriState, string> = { yes: "tak", no: "nie", unknown: "nieustalone" };
const fieldLabels: Record<string, string> = {
  title: "tytuł",
  description: "opis",
  severity: "waga",
  status: "status",
  assignee: "prowadzący",
  significant: "incydent poważny (NIS2)",
  aware_at: "chwila stwierdzenia",
  malicious: "podejrzenie działania złośliwego",
  cross_border: "wpływ transgraniczny",
  impact: "skutki",
  root_cause: "przyczyna",
  mitigation: "działania ograniczające",
  iocs: "wskaźniki naruszenia (IoC)",
};

// Ścieżka statusów i dozwolone przejścia (jak na serwerze): praca może
// wracać, zamknięcie jest ostateczne.
const statusPath: IncidentStatus[] = ["open", "investigating", "contained", "resolved", "closed"];
const transitions: Record<IncidentStatus, { to: IncidentStatus; label: string; color?: string; variant?: string }[]> = {
  open: [
    { to: "investigating", label: "Rozpocznij analizę" },
    { to: "contained", label: "Zagrożenie opanowane", variant: "light" },
    { to: "resolved", label: "Rozwiązany", variant: "light" },
  ],
  investigating: [
    { to: "contained", label: "Zagrożenie opanowane" },
    { to: "resolved", label: "Rozwiązany", variant: "light" },
    { to: "open", label: "Przywróć do otwartych", variant: "subtle" },
  ],
  contained: [
    { to: "resolved", label: "Rozwiązany" },
    { to: "investigating", label: "Wróć do analizy", variant: "subtle" },
  ],
  resolved: [
    { to: "closed", label: "Zamknij incydent", color: "gray" },
    { to: "contained", label: "Wróć do opanowanych", variant: "subtle" },
    { to: "investigating", label: "Wróć do analizy", variant: "subtle" },
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

function activityText(a: IncidentActivity): string {
  const d = a.details ?? {};
  switch (a.kind) {
    case "created":
      return `utworzył incydent (alerty: ${d.alerts ?? 0})`;
    case "field": {
      const f = String(d.field ?? a.text);
      const long = ["description", "impact", "root_cause", "mitigation", "iocs"].includes(f);
      return long ? `zmienił: ${fieldLabels[f] ?? f}` : `${fieldLabels[f] ?? f}: ${String(d.from || "—")} → ${String(d.to || "—")}`;
    }
    case "alerts_added":
      return a.text;
    case "alert_removed":
      return a.text;
    case "report_submitted":
      return `oznaczył jako wysłane do CSIRT: ${reportKindLabels[d.kind as ReportKind] ?? a.text}${d.reference ? ` (sprawa ${String(d.reference)})` : ""}`;
    case "evidence":
      return a.text;
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
  const [content, setContent] = useState(report?.content ?? "");
  const [busy, setBusy] = useState(false);
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
    a.download = `incydent-${id}-${kind}.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <Stack gap="xs">
      {submitted ? (
        <Alert color="green" icon={<IconCheck size={16} />}>
          Wysłane do CSIRT {formatDate(report!.submitted_at)} ({report!.submitted_by})
          {report!.reference ? `, sprawa ${report!.reference}` : ""}. Treść poniżej to wysłana wersja – nie da się jej zmienić.
        </Alert>
      ) : (
        <Text size="xs" c="dimmed">
          Vardr przygotowuje szkic z danych incydentu; uzupełnij pola „[uzupełnij]”, wyślij przez kanał właściwego CSIRT
          (portal, e-mail) i oznacz tutaj jako wysłane – terminy przestaną się liczyć.
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
        placeholder="Brak treści – kliknij „Szkic z danych incydentu”."
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
                  if (content.trim() && !window.confirm("Zastąpić obecną treść nowym szkicem?")) return;
                  setContent((await incidentsApi.draft(id, kind)).content);
                })
              }
            >
              Szkic z danych incydentu
            </Button>
            <Button
              size="xs"
              variant="light"
              loading={busy}
              disabled={!content.trim()}
              onClick={() =>
                void run(async () => {
                  await incidentsApi.saveReport(id, kind, content);
                  notifications.show({ color: "green", message: "Zapisano szkic" });
                  onChanged();
                })
              }
            >
              Zapisz szkic
            </Button>
            <Button size="xs" color="green" leftSection={<IconSend size={14} />} disabled={!content.trim()} onClick={() => setSubmitOpen(true)}>
              Oznacz jako wysłane
            </Button>
          </>
        )}
        <CopyButton value={content}>
          {({ copied, copy }) => (
            <Button size="xs" variant="subtle" leftSection={copied ? <IconCheck size={14} /> : <IconCopy size={14} />} onClick={copy} disabled={!content}>
              {copied ? "Skopiowano" : "Kopiuj"}
            </Button>
          )}
        </CopyButton>
        <Button size="xs" variant="subtle" leftSection={<IconDownload size={14} />} onClick={download} disabled={!content}>
          Pobierz .txt
        </Button>
      </Group>
      <Modal opened={submitOpen} onClose={() => setSubmitOpen(false)} title={`Wysłane do CSIRT: ${reportKindLabels[kind]}`} centered>
        <Stack>
          <Text size="sm">Treść z edytora zostanie zapisana jako wysłana i zamrożona. Zmiana trafi do audytu.</Text>
          <TextInput label="Chwila wysłania" type="datetime-local" value={sentAt} onChange={(e) => setSentAt(e.currentTarget.value)} />
          <TextInput
            label="Numer sprawy / zgłoszenia w CSIRT"
            placeholder="opcjonalnie"
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
            Oznacz jako wysłane
          </Button>
        </Stack>
      </Modal>
    </Stack>
  );
}

export default function IncidentDetailPage() {
  const { id: idParam } = useParams();
  const id = Number(idParam);
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
        reason: `Incydent #${x.id}: ${x.title} – paczka dowodowa`,
        agents: evidence.agents,
      });
      await incidentsApi.evidence(
        id,
        `Zlecono paczkę dowodową z archiwum NIS2 (eksport #${r.export.id}, ${formatDate(evidence.from.toISOString())} – ${formatDate(evidence.to.toISOString())}, agenci: ${evidence.agents.length || "wszyscy"}).`,
      );
      notifications.show({ color: "green", message: `Zlecono eksport #${r.export.id} – gotowy w Archiwum NIS2 → Eksport dla audytora` });
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

  return (
    <Stack>
      <Anchor component={Link} to="/incidents" size="sm">
        <Group gap={4}>
          <IconArrowLeft size={14} /> incydenty
        </Group>
      </Anchor>
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>
            #{x.id} {x.title}
          </Title>
          <Text size="xs" c="dimmed">
            założył {x.created_by} {formatDate(x.created_at)} · ostatnia zmiana {formatDate(x.updated_at)}
            {x.closed_at && ` · zamknięty ${formatDate(x.closed_at)}`}
          </Text>
        </div>
        <Group gap="xs">
          {x.significant && (
            <Badge color="red" size="lg">
              NIS2 – incydent poważny
            </Badge>
          )}
        </Group>
      </Group>

      {x.status === "closed" && (
        <Alert color="gray" icon={<IconLock size={16} />}>
          Incydent zamknięty {formatDate(x.closed_at)} – tylko do odczytu. Zamknięcia nie da się cofnąć; przy nawrocie zagrożenia
          załóż nowy incydent.
        </Alert>
      )}
      <Card withBorder>
        <Stack gap="sm">
          <Stepper active={statusPath.indexOf(x.status)} size="sm" allowNextStepsSelect={false}>
            {statusPath.map((st) => (
              <Stepper.Step key={st} label={incidentStatusLabels[st].label} />
            ))}
          </Stepper>
          {canEdit && (
            <Group gap="xs">
              {transitions[x.status].map((t) => (
                <Button
                  key={t.to}
                  size="xs"
                  color={t.color}
                  variant={t.variant ?? "filled"}
                  loading={busy}
                  leftSection={t.to === "closed" ? <IconLock size={14} /> : undefined}
                  onClick={() => {
                    if (t.to === "closed") {
                      setSummary("");
                      setCloseOpen(true);
                    } else void patch({ status: t.to });
                  }}
                >
                  {t.label}
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
                  label="Waga"
                  disabled={!canEdit || busy}
                  value={x.severity}
                  allowDeselect={false}
                  onChange={(v) => v && v !== x.severity && void patch({ severity: v as Incident["severity"] })}
                  data={Object.entries(incidentSeverityLabels).map(([value, l]) => ({ value, label: l.label }))}
                />
                <Select
                  label="Prowadzi"
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
                label="Opis"
                autosize
                minRows={2}
                readOnly={!canEdit}
                value={findings.description}
                onChange={(e) => setFindings({ ...findings, description: e.currentTarget.value })}
              />
              <Textarea
                label="Skutki (systemy, dane, usługi, osoby)"
                autosize
                minRows={2}
                readOnly={!canEdit}
                value={findings.impact}
                onChange={(e) => setFindings({ ...findings, impact: e.currentTarget.value })}
              />
              <Textarea
                label="Rodzaj zagrożenia / przyczyna"
                autosize
                minRows={2}
                readOnly={!canEdit}
                value={findings.root_cause}
                onChange={(e) => setFindings({ ...findings, root_cause: e.currentTarget.value })}
              />
              <Textarea
                label="Działania ograniczające (zastosowane i prowadzone)"
                autosize
                minRows={2}
                readOnly={!canEdit}
                value={findings.mitigation}
                onChange={(e) => setFindings({ ...findings, mitigation: e.currentTarget.value })}
              />
              <Textarea
                label="Wskaźniki naruszenia (IoC) – adresy, skróty plików, domeny"
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
                    Zapisz ustalenia
                  </Button>
                </Group>
              )}
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 5 }}>
          <Card withBorder>
            <Stack gap="xs">
              <Title order={4}>NIS2</Title>
              <Switch
                label="Incydent poważny (obowiązek zgłoszenia do CSIRT)"
                checked={x.significant}
                disabled={!canEdit || busy}
                onChange={(e) => void patch({ significant: e.currentTarget.checked })}
              />
              <TextInput
                label="Stwierdzony (początek terminów)"
                type="datetime-local"
                disabled={!canEdit || busy || !x.significant}
                value={toLocalInput(x.aware_at)}
                onChange={(e) => e.currentTarget.value && void patch({ aware_at: new Date(e.currentTarget.value).toISOString() })}
              />
              <Group grow>
                <Select
                  label="Podejrzenie działania złośliwego"
                  disabled={!canEdit || busy}
                  value={x.malicious}
                  allowDeselect={false}
                  onChange={(v) => v && v !== x.malicious && void patch({ malicious: v as TriState })}
                  data={Object.entries(triLabels).map(([value, label]) => ({ value, label }))}
                />
                <Select
                  label="Wpływ transgraniczny"
                  disabled={!canEdit || busy}
                  value={x.cross_border}
                  allowDeselect={false}
                  onChange={(v) => v && v !== x.cross_border && void patch({ cross_border: v as TriState })}
                  data={Object.entries(triLabels).map(([value, label]) => ({ value, label }))}
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
                  Po oznaczeniu jako poważny panel liczy terminy zgłoszeń i przypomina o nich na kanałach powiadomień
                  (zdarzenie „incydenty”).
                </Text>
              )}
              {can("archive", "export") && evidence && (
                <Button
                  size="xs"
                  variant="light"
                  leftSection={<IconFileCertificate size={14} />}
                  loading={busy}
                  disabled={evidence.tooLong}
                  title={evidence.tooLong ? "zakres alertów dłuższy niż 31 dni – zleć eksport ręcznie w Archiwum" : undefined}
                  onClick={() => void requestEvidence()}
                >
                  Paczka dowodowa z archiwum NIS2
                </Button>
              )}
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>

      {x.significant && (
        <Card withBorder>
          <Title order={4} mb="xs">
            Zgłoszenia do CSIRT
          </Title>
          <Tabs value={tab} onChange={setTab}>
            <Tabs.List>
              {(Object.keys(reportKindLabels) as ReportKind[]).map((k) => (
                <Tabs.Tab key={k} value={k} rightSection={repByKind[k]?.submitted_at ? <IconCheck size={12} color="green" /> : null}>
                  {reportKindLabels[k]}
                </Tabs.Tab>
              ))}
            </Tabs.List>
            {(Object.keys(reportKindLabels) as ReportKind[]).map((k) => (
              <Tabs.Panel key={k} value={k} pt="xs">
                {tab === k && <ReportEditor id={id} kind={k} report={repByKind[k]} canEdit={canEdit} onChanged={load} />}
              </Tabs.Panel>
            ))}
          </Tabs>
        </Card>
      )}

      <Card withBorder>
        <Title order={4} mb="xs">
          Alerty ({alerts.length})
        </Title>
        {alerts.length === 0 ? (
          <Text size="sm" c="dimmed">
            Brak alertów. Dodasz je z listy alertów (zaznacz → „Do incydentu”) albo ze szczegółów alertu.
          </Text>
        ) : (
          <Table.ScrollContainer minWidth={800}>
            <Table verticalSpacing={4}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Pierwsze</Table.Th>
                  <Table.Th>Poziom</Table.Th>
                  <Table.Th>Reguła</Table.Th>
                  <Table.Th>Komputer / konto</Table.Th>
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
                        {a.rule_title}
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
                            window.confirm(`Usunąć alert #${a.alert_id} z incydentu?`) &&
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

      <Modal opened={closeOpen} onClose={() => setCloseOpen(false)} title={`Zamknięcie incydentu #${x.id}`} centered>
        <Stack>
          <Alert color="orange">
            Zamknięcie jest ostateczne: incydent stanie się tylko do odczytu (bez zmian, notatek, alertów i zgłoszeń).
            {x.significant && " Incydent poważny można zamknąć po oznaczeniu sprawozdania końcowego jako wysłanego."}
          </Alert>
          <Textarea
            label="Podsumowanie"
            description="przebieg, skutki, wnioski – trafi do osi czasu"
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
            Zamknij incydent
          </Button>
        </Stack>
      </Modal>

      <Card withBorder>
        <Title order={4} mb="xs">
          Oś czasu
        </Title>
        {canEdit && (
          <Group align="flex-end" mb="sm">
            <Textarea
              style={{ flex: 1 }}
              autosize
              minRows={1}
              placeholder="Notatka: ustalenia, decyzje, kontakt z CSIRT…"
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
              Dodaj notatkę
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
                <Text size="sm">{activityText(a)}</Text>
              )}
            </Timeline.Item>
          ))}
        </Timeline>
      </Card>
    </Stack>
  );
}
