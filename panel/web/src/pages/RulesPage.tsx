import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert as MAlert,
  Anchor,
  Badge,
  Button,
  Checkbox,
  Code,
  Group,
  Modal,
  MultiSelect,
  Pagination,
  PasswordInput,
  ScrollArea,
  SegmentedControl,
  Select,
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
import {
  IconDownload,
  IconFlask,
  IconHistory,
  IconFileCode,
  IconHourglass,
  IconLink,
  IconPencil,
  IconSearch,
  IconTrash,
} from "@tabler/icons-react";
import { Link } from "react-router-dom";
import {
  ApiError,
  alertsApi,
  formatDate,
  levelLabels,
  panelRuleId,
  rulesApi,
  type BulkRuleAction,
  type RuleAttribution,
  type RuleInfo,
  type RuleVersion,
} from "../api";
import { useAuth } from "../auth";
import { AttackTags, AttributionLine } from "../attack";
import { lineDiff } from "../diff";
import RuleBulkModal, { bulkLabels } from "./RuleBulkModal";
import RuleTester from "./RuleTester";
import SigmaImportHelp from "./SigmaImportHelp";

const modeLabels: Record<string, string> = {
  stream: "w locie",
  index_query: "zapytania",
  both: "oba silniki",
  system: "wbudowana",
  correlation: "korelacja",
};

function modeLabel(r: RuleInfo): string {
  if (r.mode === "correlation" && r.file === "(wbudowana)") return "korelacja (wbudowana)";
  return modeLabels[r.mode] ?? r.mode;
}

// Tryb próbny: reguły Sigmy oceniane przez detektor (bez korelacji, reguł
// wbudowanych i reguł bazowych korelacji).
export function trialCapable(r: RuleInfo): boolean {
  return r.mode !== "system" && r.mode !== "correlation" && !r.description.startsWith("Reguła bazowa korelacji");
}

export function ruleSource(r: RuleInfo): "sigmahq" | "panel" | "builtin" | "own" {
  if (r.file.startsWith("sigmahq/")) return "sigmahq";
  if (r.file.startsWith("panel/")) return "panel";
  if (r.file === "(wbudowana)" || r.mode === "system") return "builtin";
  return "own";
}

const pageSize = 100;

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
vardr:
  group_by: [TargetUserName]
  threshold:
    count: 5
    window: 10m
`;

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
  const { can } = useAuth();
  const admin = can("rules", "write");
  const canTest = can("rules", "test");
  const [rules, setRules] = useState<RuleInfo[]>([]);
  const [errors, setErrors] = useState<{ file: string; error: string }[]>([]);
  const [configured, setConfigured] = useState(true);
  const [error, setError] = useState("");
  const [show, setShow] = useState<RuleInfo | null>(null);
  const [tab, setTab] = useState<string | null>("source");
  const [testNew, setTestNew] = useState(false);
  const [toggle, setToggle] = useState<{ rule: RuleInfo; enabled: boolean | null; trial?: boolean } | null>(null);
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const [needPassword, setNeedPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [del, setDel] = useState<{ id: string; title: string } | null>(null);
  const [sigmaHelp, setSigmaHelp] = useState(false);
  const [attributions, setAttributions] = useState<Record<string, RuleAttribution>>({});
  const [q, setQ] = useState("");
  const [source, setSource] = useState("all");
  const [stateF, setStateF] = useState<string | null>("all");
  const [levels, setLevels] = useState<string[]>([]);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulk, setBulk] = useState<BulkRuleAction | null>(null);

  const load = useCallback(() => {
    alertsApi
      .rules()
      .then((r) => {
        setRules(r.rules);
        setAttributions(r.attributions ?? {});
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
      const r = await rulesApi.setEnabled(toggle.rule.id, toggle.enabled, reason, password, !!toggle.trial);
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
  const applyDelete = async () => {
    if (!del) return;
    setBusy(true);
    try {
      const r = await rulesApi.deletePanelRule(del.id, reason, password);
      notifications.show({ color: "green", message: r.message });
      setDel(null);
      setShow(null);
      setReason("");
      setPassword("");
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };
  const disabling = toggle ? toggle.rule.enabled && (!!toggle.trial || !(toggle.enabled ?? toggle.rule.file_enabled)) : false;
  const trials = rules.filter((r) => r.override?.trial).length;

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rules.filter((r) => {
      if (source !== "all" && ruleSource(r) !== source) return false;
      if (stateF === "on" && !r.enabled) return false;
      if (stateF === "off" && (r.enabled || r.override?.trial)) return false;
      if (stateF === "trial" && !r.override?.trial) return false;
      if (stateF === "panel" && !r.override) return false;
      if (levels.length > 0 && !levels.includes(r.level)) return false;
      if (!needle) return true;
      return (
        r.title.toLowerCase().includes(needle) ||
        r.id.toLowerCase().includes(needle) ||
        r.file.toLowerCase().includes(needle) ||
        r.tags.some((t) => t.toLowerCase().includes(needle))
      );
    });
  }, [rules, q, source, stateF, levels]);
  useEffect(() => setPage(1), [q, source, stateF, levels]);
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const shown = filtered.slice((page - 1) * pageSize, page * pageSize);
  const allFiltered = filtered.length > 0 && filtered.every((r) => selected.has(r.id));
  const toggleSel = (id: string, on: boolean) =>
    setSelected((s) => {
      const n = new Set(s);
      if (on) n.add(id);
      else n.delete(id);
      return n;
    });

  return (
    <Stack>
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>Reguły detekcji</Title>
          <Text c="dimmed" size="sm" maw={820}>
            Reguły w formacie Sigma (YAML) z katalogu <Code>rules/</Code> w repozytorium – wdrażane poleceniem{" "}
            <Code>deploy.sh rules</Code>, detektor przeładowuje je w ciągu 30 s. Każda zmiana treści to nowa wersja (historia
            w szczegółach). Administrator może regułę wyłączyć albo włączyć z panelu – z powodem i w audycie. Reguły
            korelacyjne z kreatora są zapisywane w panelu (plik <Code>panel/…</Code>).
          </Text>
        </div>
        {canTest && (
          <Group gap="xs">
            <Button variant="light" leftSection={<IconLink size={16} />} component={Link} to="/rules/correlation">
              Nowa korelacja (kreator)
            </Button>
            <Button variant="light" leftSection={<IconFlask size={16} />} onClick={() => setTestNew(true)}>
              Przetestuj nową regułę
            </Button>
            <Button variant="light" color="yellow" leftSection={<IconHourglass size={16} />} component={Link} to="/rules/trial">
              Próby reguł{trials > 0 ? ` (${trials})` : ""}
            </Button>
            {admin && (
              <Button variant="subtle" leftSection={<IconDownload size={16} />} onClick={() => setSigmaHelp(true)}>
                Import reguł SigmaHQ
              </Button>
            )}
          </Group>
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
        <Group gap="xs" align="flex-end">
          <TextInput
            placeholder="szukaj: tytuł, id, plik, tag (np. attack.t1059)"
            leftSection={<IconSearch size={14} />}
            value={q}
            onChange={(e) => setQ(e.currentTarget.value)}
            w={320}
          />
          <SegmentedControl
            value={source}
            onChange={setSource}
            data={[
              { value: "all", label: "Wszystkie" },
              { value: "own", label: "Własne" },
              { value: "sigmahq", label: "SigmaHQ" },
              { value: "panel", label: "Z panelu" },
              { value: "builtin", label: "Wbudowane" },
            ]}
          />
          <Select
            w={170}
            value={stateF}
            onChange={setStateF}
            allowDeselect={false}
            data={[
              { value: "all", label: "każdy stan" },
              { value: "on", label: "włączone" },
              { value: "off", label: "wyłączone" },
              { value: "trial", label: "w trybie próbnym" },
              { value: "panel", label: "ustawione w panelu" },
            ]}
          />
          <MultiSelect
            w={260}
            placeholder={levels.length ? "" : "każdy poziom"}
            value={levels}
            onChange={setLevels}
            clearable
            data={Object.entries(levelLabels).map(([value, l]) => ({ value, label: l.label }))}
          />
          <Text size="sm" c="dimmed">
            {filtered.length} z {rules.length}
          </Text>
        </Group>
      )}
      {admin && selected.size > 0 && (
        <Group gap="xs">
          <Text size="sm" fw={500}>
            Zaznaczone: {selected.size}
          </Text>
          {(["trial", "enable", "disable", "file"] as BulkRuleAction[]).map((a) => (
            <Button
              key={a}
              size="xs"
              variant="light"
              color={a === "disable" ? "red" : a === "trial" ? "yellow" : undefined}
              onClick={() => setBulk(a)}
            >
              {bulkLabels[a]}
            </Button>
          ))}
          <Button size="xs" variant="subtle" onClick={() => setSelected(new Set())}>
            wyczyść zaznaczenie
          </Button>
        </Group>
      )}
      {rules.length > 0 && (
        <Table.ScrollContainer minWidth={980}>
          <Table striped highlightOnHover verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                {admin && (
                  <Table.Th w={36}>
                    <Checkbox
                      size="xs"
                      checked={allFiltered}
                      indeterminate={!allFiltered && filtered.some((r) => selected.has(r.id))}
                      onChange={(e) => {
                        const on = e.currentTarget.checked;
                        setSelected((s) => {
                          const n = new Set(s);
                          for (const r of filtered) {
                            if (on) n.add(r.id);
                            else n.delete(r.id);
                          }
                          return n;
                        });
                      }}
                      aria-label="zaznacz wszystkie z filtra"
                      title={`zaznacz wszystkie reguły z filtra (${filtered.length})`}
                    />
                  </Table.Th>
                )}
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
              {shown.map((r) => (
                <Table.Tr
                  key={r.id}
                  style={{ cursor: "pointer", opacity: r.enabled || r.override?.trial ? 1 : 0.55 }}
                  onClick={() => {
                    setShow(r);
                    setTab("source");
                  }}
                >
                  {admin && (
                    <Table.Td onClick={(e) => e.stopPropagation()}>
                      <Checkbox
                        size="xs"
                        checked={selected.has(r.id)}
                        onChange={(e) => toggleSel(r.id, e.currentTarget.checked)}
                        aria-label="zaznacz regułę"
                      />
                    </Table.Td>
                  )}
                  <Table.Td onClick={(e) => e.stopPropagation()}>
                    <Group gap={4} wrap="nowrap">
                      <Switch
                        size="sm"
                        checked={r.enabled}
                        disabled={!admin || r.mode === "system"}
                        onChange={(e) => setToggle({ rule: r, enabled: e.currentTarget.checked })}
                        aria-label="reguła włączona"
                      />
                      {r.override?.trial && (
                        <Tooltip
                          multiline
                          w={300}
                          label={`Tryb próbny od ${formatDate(r.override.changed_at)} (${r.override.changed_by}${r.override.reason ? ` – ${r.override.reason}` : ""}): trafienia bez alertów, wyniki w „Próbach reguł”.`}
                        >
                          <Badge size="xs" color="yellow" component={Link} to="/rules/trial" style={{ cursor: "pointer" }}>
                            próbna
                          </Badge>
                        </Tooltip>
                      )}
                      {r.override && !r.override.trial && (
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
                    <AttackTags tags={r.tags} size="xs" />
                  </Table.Td>
                  <Table.Td>{modeLabel(r)}</Table.Td>
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
      {pages > 1 && <Pagination total={pages} value={page} onChange={setPage} size="sm" />}
      <RuleBulkModal
        ids={[...selected]}
        action={bulk}
        onClose={() => setBulk(null)}
        onDone={() => {
          setBulk(null);
          setSelected(new Set());
          load();
        }}
      />

      <Modal opened={!!show} onClose={() => setShow(null)} title={show?.title} size="xl">
        {show && (
          <Stack gap="xs">
            <AttributionLine a={attributions[show.id]} />
            <AttackTags tags={show.tags} />
            <Group gap={4}>
              {show.tags
                .filter((t) => !t.toLowerCase().startsWith("attack."))
                .map((t) => (
                  <Badge key={t} variant="outline" size="sm">
                    {t}
                  </Badge>
                ))}
            </Group>
            <Text size="xs" c="dimmed">
              id {show.id} · wersja {show.version} · wczytana {formatDate(show.loaded_at)}
            </Text>
            {panelRuleId(show.file) && (
              <Group gap="xs">
                <Badge variant="light" color="grape">
                  reguła z panelu (kreator korelacji)
                </Badge>
                {admin && (
                  <>
                    <Button
                      size="xs"
                      variant="light"
                      leftSection={<IconPencil size={14} />}
                      component={Link}
                      to={`/rules/correlation?edit=${encodeURIComponent(panelRuleId(show.file)!)}`}
                    >
                      Edytuj
                    </Button>
                    <Button
                      size="xs"
                      variant="light"
                      color="red"
                      leftSection={<IconTrash size={14} />}
                      onClick={() => setDel({ id: panelRuleId(show.file)!, title: show.title })}
                    >
                      Usuń
                    </Button>
                  </>
                )}
              </Group>
            )}
            <Tabs value={tab} onChange={setTab}>
              <Tabs.List>
                <Tabs.Tab value="source" leftSection={<IconFileCode size={14} />}>
                  Treść
                </Tabs.Tab>
                <Tabs.Tab value="versions" leftSection={<IconHistory size={14} />}>
                  Wersje
                </Tabs.Tab>
                {canTest && show.mode !== "system" && !(show.mode === "correlation" && show.file === "(wbudowana)") && (
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

      <Modal opened={!!del} onClose={() => setDel(null)} title={del ? `Usunięcie reguły „${del.title}”` : ""} centered>
        {del && (
          <Stack>
            <MAlert color="orange">
              Usunięta zostanie cała reguła z panelu (korelacja i jej reguły bazowe z tego samego zapisu). Historia wersji i alerty
              zostają. Podaj powód (trafi do audytu) i potwierdź hasłem.
            </MAlert>
            <Textarea label="Powód" autosize minRows={2} value={reason} onChange={(e) => setReason(e.currentTarget.value)} />
            <PasswordInput label="Twoje hasło" value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
            <Group justify="flex-end">
              <Button color="red" loading={busy} disabled={reason.trim().length < 3 || !password} onClick={() => void applyDelete()}>
                Usuń regułę
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>

      <Modal opened={sigmaHelp} onClose={() => setSigmaHelp(false)} title="Import reguł SigmaHQ" size="xl">
        {sigmaHelp && <SigmaImportHelp />}
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
        title={
          toggle
            ? `${toggle.trial ? "Tryb próbny" : disabling ? "Wyłączenie" : "Włączenie"} reguły „${toggle.rule.title}”`
            : ""
        }
        centered
      >
        {toggle && (
          <Stack>
            {toggle.trial && (
              <MAlert color="yellow">
                W trybie próbnym reguła liczy trafienia (komputery, dni, ostatnie zdarzenie) bez alertów i powiadomień – wyniki
                w „Próbach reguł”. Po tygodniu–dwóch widać, czy można ją włączyć.
              </MAlert>
            )}
            {disabling && (
              <MAlert color="orange">
                {toggle.trial ? "Na czas próby reguła" : "Wyłączona reguła"} nie wywoła alertów – także przy prawdziwym ataku. Podaj
                powód (trafi do audytu) i potwierdź hasłem.
              </MAlert>
            )}
            {!toggle.trial && toggle.enabled && trialCapable(toggle.rule) && !toggle.rule.override?.trial && (
              <Button size="xs" variant="light" color="yellow" leftSection={<IconHourglass size={14} />}
                onClick={() => setToggle({ ...toggle, trial: true })}>
                Najpierw tryb próbny (bez alertów)
              </Button>
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
                {toggle.enabled === null
                  ? "Przywróć z pliku"
                  : toggle.trial
                    ? "Uruchom próbę"
                    : disabling
                      ? "Wyłącz regułę"
                      : "Włącz regułę"}
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
