import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert as MAlert,
  Anchor,
  Badge,
  Button,
  Code,
  Group,
  Modal,
  PasswordInput,
  ScrollArea,
  Select,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  Textarea,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconFlask, IconHistory, IconFileCode } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import {
  ApiError,
  alertsApi,
  formatDate,
  levelLabels,
  rulesApi,
  type RuleInfo,
  type RuleTestResult,
  type RuleVersion,
} from "../api";
import { useAuth } from "../auth";
import { lineDiff } from "../diff";

const modeLabels: Record<string, string> = {
  stream: "w locie",
  index_query: "zapytania",
  both: "oba silniki",
  system: "wbudowana",
  correlation: "korelacja (wbudowana)",
};

function fmtDuration(s: number): string {
  if (s % 3600 === 0) return `${s / 3600} h`;
  if (s % 60 === 0) return `${s / 60} min`;
  return `${s} s`;
}

const newRuleTemplate = `title: Nowa reguła
id: moja-regula-1
level: medium
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
heimdall:
  group_by: [TargetUserName]
  threshold:
    count: 5
    window: 10m
`;

// Test reguły na zdarzeniach z ostatnich godzin (bez wdrażania).
function RuleTester({ initial }: { initial: string }) {
  const [source, setSource] = useState(initial);
  const [hours, setHours] = useState("24");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [res, setRes] = useState<RuleTestResult | null>(null);
  const [sql, setSql] = useState("");
  useEffect(() => setSource(initial), [initial]);

  const run = async () => {
    setBusy(true);
    setErr("");
    setRes(null);
    try {
      const r = await rulesApi.test(source, Number(hours));
      if (!r.ok) setErr(r.error ?? "błąd");
      else {
        // Puste listy mogą przyjść jako null (starszy serwer) – bez tego strona się wywracała.
        setRes(r.result ? { ...r.result, events: r.result.events ?? [], alerts: r.result.alerts ?? [] } : null);
        setSql(r.sql ?? "");
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack gap="xs">
      <Text size="xs" c="dimmed">
        Reguła (YAML) jest sprawdzana i wykonywana na zdarzeniach z ClickHouse – nic nie jest wdrażane ani zapisywane. Alerty liczone
        tak jak w detektorze (łączenie, progi). Zmienioną regułę wdraża się plikiem w repozytorium (<Code>deploy.sh rules</Code>).
      </Text>
      <Textarea
        autosize
        minRows={10}
        maxRows={24}
        spellCheck={false}
        styles={{ input: { fontFamily: "monospace", fontSize: 12 } }}
        value={source}
        onChange={(e) => setSource(e.currentTarget.value)}
      />
      <Group>
        <Select
          w={180}
          allowDeselect={false}
          value={hours}
          onChange={(v) => setHours(v ?? "24")}
          data={[
            { value: "1", label: "ostatnia godzina" },
            { value: "24", label: "ostatnie 24 h" },
            { value: "72", label: "ostatnie 3 dni" },
            { value: "168", label: "ostatnie 7 dni" },
          ]}
        />
        <Button leftSection={<IconFlask size={16} />} loading={busy} onClick={() => void run()}>
          Przetestuj
        </Button>
      </Group>
      {err && (
        <MAlert color="red" title="Reguła nie przeszła">
          <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>
            {err}
          </Text>
        </MAlert>
      )}
      {res && (
        <Stack gap="xs">
          <MAlert color={res.alerts_total > 0 ? "orange" : "green"}>
            <Text size="sm">
              Pasujących zdarzeń: <b>{res.matched}</b> · alertów, które by powstały: <b>{res.alerts_total}</b>
              {res.truncated ? " (z pierwszych 20 000 zdarzeń)" : ""} · {res.took_ms} ms
            </Text>
          </MAlert>
          {res.alerts.length > 0 && (
            <Table fz="xs" verticalSpacing={2} withTableBorder>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Klucz / komputer</Table.Th>
                  <Table.Th>Zdarzenia</Table.Th>
                  <Table.Th>Od</Table.Th>
                  <Table.Th>Do</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {res.alerts.slice(0, 30).map((a, i) => (
                  <Table.Tr key={i}>
                    <Table.Td>
                      {a.key
                        ? Object.entries(a.key)
                            .map(([k, v]) => `${k}=${v}`)
                            .join(", ")
                        : a.host}
                    </Table.Td>
                    <Table.Td>{a.events}</Table.Td>
                    <Table.Td>{formatDate(a.first)}</Table.Td>
                    <Table.Td>{formatDate(a.last)}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          )}
          {res.events.length > 0 && (
            <>
              <Text size="sm" fw={500}>
                Ostatnie pasujące zdarzenia
              </Text>
              <Table fz="xs" verticalSpacing={2} withTableBorder>
                <Table.Tbody>
                  {res.events.slice(0, 20).map((e) => (
                    <Table.Tr key={e.event_id}>
                      <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(e.timestamp)}</Table.Td>
                      <Table.Td>{e.code}</Table.Td>
                      <Table.Td>{e.host}</Table.Td>
                      <Table.Td>{e.user}</Table.Td>
                      <Table.Td style={{ wordBreak: "break-all" }}>{e.summary}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </>
          )}
          {sql && (
            <details>
              <summary>
                <Text span size="xs" c="dimmed">
                  warunek SQL (silnik zapytań)
                </Text>
              </summary>
              <Code block fz="xs">
                {sql}
              </Code>
            </details>
          )}
        </Stack>
      )}
    </Stack>
  );
}

function Versions({ id }: { id: string }) {
  const [versions, setVersions] = useState<RuleVersion[]>([]);
  const [sel, setSel] = useState<number | null>(null);
  useEffect(() => {
    rulesApi
      .versions(id)
      .then((r) => {
        setVersions(r.versions);
        setSel(r.versions[0]?.version ?? null);
      })
      .catch(() => setVersions([]));
  }, [id]);
  const cur = versions.find((v) => v.version === sel);
  const prev = versions.find((v) => sel !== null && v.version === sel - 1);
  const diff = useMemo(() => (cur && prev ? lineDiff(prev.source, cur.source) : null), [cur, prev]);
  if (versions.length === 0) return <Text size="sm">Brak historii.</Text>;
  return (
    <Stack gap="xs">
      <Group gap="xs">
        {versions.map((v) => (
          <Badge
            key={v.version}
            variant={v.version === sel ? "filled" : "light"}
            style={{ cursor: "pointer" }}
            onClick={() => setSel(v.version)}
            title={`${formatDate(v.loaded_at)} · ${v.sha256.slice(0, 12)}`}
          >
            v{v.version} · {formatDate(v.loaded_at)}
          </Badge>
        ))}
      </Group>
      {cur && (
        <Text size="xs" c="dimmed">
          v{cur.version}: wczytana {formatDate(cur.loaded_at)} z pliku {cur.file} · SHA-256 {cur.sha256.slice(0, 16)}…
          {prev ? ` · zmiany względem v${prev.version}:` : " · pierwsza wersja"}
        </Text>
      )}
      <ScrollArea.Autosize mah={460}>
        {diff ? (
          <Code block fz="xs">
            {diff.map((d, i) => (
              <div
                key={i}
                style={{
                  background: d.op === "+" ? "rgba(47,158,68,.15)" : d.op === "-" ? "rgba(224,49,49,.15)" : undefined,
                }}
              >
                {d.op} {d.line}
              </div>
            ))}
          </Code>
        ) : (
          cur && <Code block>{cur.source}</Code>
        )}
      </ScrollArea.Autosize>
    </Stack>
  );
}

export default function RulesPage() {
  const { user } = useAuth();
  const admin = user?.role === "admin";
  const canTest = admin || user?.role === "analyst";
  const [rules, setRules] = useState<RuleInfo[]>([]);
  const [errors, setErrors] = useState<{ file: string; error: string }[]>([]);
  const [configured, setConfigured] = useState(true);
  const [error, setError] = useState("");
  const [show, setShow] = useState<RuleInfo | null>(null);
  const [tab, setTab] = useState<string | null>("source");
  const [testNew, setTestNew] = useState(false);
  const [toggle, setToggle] = useState<{ rule: RuleInfo; enabled: boolean | null } | null>(null);
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const [needPassword, setNeedPassword] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    alertsApi
      .rules()
      .then((r) => {
        setRules(r.rules);
        setErrors(r.errors);
        setConfigured(r.configured);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);
  useEffect(() => load(), [load]);

  const applyToggle = async () => {
    if (!toggle) return;
    setBusy(true);
    try {
      const r = await rulesApi.setEnabled(toggle.rule.id, toggle.enabled, reason, password);
      notifications.show({ color: "green", message: r.message });
      setToggle(null);
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
  const disabling = toggle ? toggle.rule.enabled && !(toggle.enabled ?? toggle.rule.file_enabled) : false;

  return (
    <Stack>
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>Reguły detekcji</Title>
          <Text c="dimmed" size="sm" maw={820}>
            Reguły w formacie Sigma (YAML) z katalogu <Code>rules/</Code> w repozytorium – wdrażane poleceniem{" "}
            <Code>deploy.sh rules</Code>, detektor przeładowuje je w ciągu 30 s. Każda zmiana treści to nowa wersja (historia
            w szczegółach). Administrator może regułę wyłączyć albo włączyć z panelu – z powodem i w audycie.
          </Text>
        </div>
        {canTest && (
          <Button variant="light" leftSection={<IconFlask size={16} />} onClick={() => setTestNew(true)}>
            Przetestuj nową regułę
          </Button>
        )}
      </Group>
      {error && <MAlert color="red">{error}</MAlert>}
      {!configured && <MAlert color="gray">Detektor (siem-detector) jeszcze nie działał – brak wczytanych reguł.</MAlert>}
      {errors.length > 0 && (
        <MAlert color="red" title={`Pliki z błędami (${errors.length}) – te reguły nie działają`}>
          {errors.map((e) => (
            <Text size="sm" key={e.file}>
              <Code>{e.file}</Code>: {e.error}
            </Text>
          ))}
        </MAlert>
      )}
      {rules.length > 0 && (
        <Table.ScrollContainer minWidth={980}>
          <Table striped highlightOnHover verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Włączona</Table.Th>
                <Table.Th>Poziom</Table.Th>
                <Table.Th>Reguła</Table.Th>
                <Table.Th>Silnik</Table.Th>
                <Table.Th>Próg / łączenie</Table.Th>
                <Table.Th>Otwarte alerty</Table.Th>
                <Table.Th>Plik</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {rules.map((r) => (
                <Table.Tr
                  key={r.id}
                  style={{ cursor: "pointer", opacity: r.enabled ? 1 : 0.55 }}
                  onClick={() => {
                    setShow(r);
                    setTab("source");
                  }}
                >
                  <Table.Td onClick={(e) => e.stopPropagation()}>
                    <Group gap={4} wrap="nowrap">
                      <Switch
                        size="sm"
                        checked={r.enabled}
                        disabled={!admin || r.mode === "system"}
                        onChange={(e) => setToggle({ rule: r, enabled: e.currentTarget.checked })}
                        aria-label="reguła włączona"
                      />
                      {r.override && (
                        <Tooltip
                          multiline
                          w={300}
                          label={`Ustawione w panelu: ${r.override.changed_by}, ${formatDate(r.override.changed_at)}${r.override.reason ? ` – ${r.override.reason}` : ""}. W pliku: ${r.file_enabled ? "włączona" : "wyłączona"}.`}
                        >
                          <Badge size="xs" variant="outline" color="grape">
                            panel
                          </Badge>
                        </Tooltip>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Badge color={levelLabels[r.level].color}>{levelLabels[r.level].label}</Badge>
                  </Table.Td>
                  <Table.Td maw={420}>
                    <Text size="sm" fw={500}>
                      {r.title}
                    </Text>
                    <Text size="xs" c="dimmed" lineClamp={1}>
                      {r.description}
                    </Text>
                  </Table.Td>
                  <Table.Td>{modeLabels[r.mode] ?? r.mode}</Table.Td>
                  <Table.Td>
                    {r.threshold && (
                      <Text size="xs" fw={500}>
                        próg: {r.threshold.count} {r.threshold.distinct ? `różnych ${r.threshold.distinct}` : "zdarzeń"} w{" "}
                        {fmtDuration(r.threshold.window_s)}
                      </Text>
                    )}
                    {r.group_by.length ? (
                      <Text size="xs">
                        {r.group_by.join(", ")} / {fmtDuration(r.suppress_s)}
                      </Text>
                    ) : r.threshold ? null : (
                      <Text size="xs" c="dimmed">
                        każde zdarzenie osobno
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td onClick={(e) => e.stopPropagation()}>
                    {r.open_alerts > 0 ? (
                      <Anchor component={Link} to={`/alerts?rule=${encodeURIComponent(r.id)}`} size="sm">
                        {r.open_alerts}
                      </Anchor>
                    ) : (
                      "0"
                    )}
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs" ff="monospace">
                      {r.file} {r.version > 0 && <Badge size="xs" variant="light">v{r.version}</Badge>}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}

      <Modal opened={!!show} onClose={() => setShow(null)} title={show?.title} size="xl">
        {show && (
          <Stack gap="xs">
            <Group gap={4}>
              {show.tags.map((t) => (
                <Badge key={t} variant="outline" size="sm">
                  {t}
                </Badge>
              ))}
            </Group>
            <Text size="xs" c="dimmed">
              id {show.id} · wersja {show.version} · wczytana {formatDate(show.loaded_at)}
            </Text>
            <Tabs value={tab} onChange={setTab}>
              <Tabs.List>
                <Tabs.Tab value="source" leftSection={<IconFileCode size={14} />}>
                  Treść
                </Tabs.Tab>
                <Tabs.Tab value="versions" leftSection={<IconHistory size={14} />}>
                  Wersje
                </Tabs.Tab>
                {canTest && show.mode !== "system" && show.mode !== "correlation" && (
                  <Tabs.Tab value="test" leftSection={<IconFlask size={14} />}>
                    Test
                  </Tabs.Tab>
                )}
              </Tabs.List>
              <Tabs.Panel value="source" pt="xs">
                <ScrollArea.Autosize mah={500}>
                  <Code block>{show.source}</Code>
                </ScrollArea.Autosize>
              </Tabs.Panel>
              <Tabs.Panel value="versions" pt="xs">
                {tab === "versions" && <Versions id={show.id} />}
              </Tabs.Panel>
              <Tabs.Panel value="test" pt="xs">
                {tab === "test" && <RuleTester initial={show.source ?? ""} />}
              </Tabs.Panel>
            </Tabs>
          </Stack>
        )}
      </Modal>

      <Modal opened={testNew} onClose={() => setTestNew(false)} title="Test nowej reguły" size="xl">
        {testNew && <RuleTester initial={newRuleTemplate} />}
      </Modal>

      <Modal
        opened={!!toggle}
        onClose={() => {
          setToggle(null);
          setNeedPassword(false);
        }}
        title={toggle ? `${disabling ? "Wyłączenie" : "Włączenie"} reguły „${toggle.rule.title}”` : ""}
        centered
      >
        {toggle && (
          <Stack>
            {disabling && (
              <MAlert color="orange">
                Wyłączona reguła nie wywoła alertów – także przy prawdziwym ataku. Podaj powód (trafi do audytu) i potwierdź hasłem.
              </MAlert>
            )}
            <Textarea
              label="Powód"
              description={disabling ? "np. fałszywe alarmy z serwera kopii do czasu poprawki reguły" : "opcjonalnie"}
              autosize
              minRows={2}
              value={reason}
              onChange={(e) => setReason(e.currentTarget.value)}
            />
            {(needPassword || disabling) && (
              <PasswordInput label="Twoje hasło" value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
            )}
            <Group justify="space-between">
              {toggle.rule.override ? (
                <Button
                  variant="subtle"
                  size="xs"
                  onClick={() => setToggle({ rule: toggle.rule, enabled: null })}
                  disabled={toggle.enabled === null}
                >
                  wróć do ustawienia z pliku ({toggle.rule.file_enabled ? "włączona" : "wyłączona"})
                </Button>
              ) : (
                <span />
              )}
              <Button
                color={disabling ? "red" : undefined}
                loading={busy}
                disabled={disabling && (reason.trim().length < 3 || !password)}
                onClick={() => void applyToggle()}
              >
                {toggle.enabled === null ? "Przywróć z pliku" : disabling ? "Wyłącz regułę" : "Włącz regułę"}
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
