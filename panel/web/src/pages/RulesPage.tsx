// SPDX-License-Identifier: AGPL-3.0-or-later

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
  ruleText,
  rulesApi,
  type BulkRuleAction,
  type RuleAttribution,
  type RuleInfo,
  type RuleVersion,
} from "../api";
import { useTranslation } from "react-i18next";
import i18n, { serverText } from "../i18n";
import { useAuth } from "../auth";
import { AttackTags, AttributionLine } from "../attack";
import { lineDiff } from "../diff";
import RuleBulkModal, { bulkLabels } from "./RuleBulkModal";
import RuleTester from "./RuleTester";
import SigmaImportHelp from "./SigmaImportHelp";

function modeLabel(r: RuleInfo): string {
  if (r.mode === "correlation" && r.file === "(wbudowana)") return i18n.t("rules:mode.builtinCorrelation");
  return i18n.t(`rules:mode.${r.mode}`, { defaultValue: r.mode });
}

// Tryb próbny: reguły Sigmy oceniane przez detektor (bez korelacji, reguł
// wbudowanych i reguł bazowych korelacji).
export function trialCapable(r: RuleInfo): boolean {
  if (r.mode === "system" || r.mode === "correlation") return false;
  if (r.file.startsWith("panel/")) return false; // reguły bazowe z kreatora korelacji
  return !r.description.startsWith("Reguła bazowa korelacji");
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

const newRuleTemplate = () => `title: ${i18n.t("rules:newRuleTitle")}
id: ${i18n.t("rules:newRuleId")}
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
  const { t } = useTranslation("rules");
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
  if (versions.length === 0) return <Text size="sm">{t("versions.none")}</Text>;
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
          {t("versions.info", { version: cur.version, date: formatDate(cur.loaded_at), file: cur.file, sha: cur.sha256.slice(0, 16) })}
          {prev ? t("versions.changesSince", { version: prev.version }) : t("versions.first")}
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
  const { t } = useTranslation("rules");
  const { can } = useAuth();
  const admin = can("rules", "write");
  const canTest = can("rules", "test");
  const [rules, setRules] = useState<RuleInfo[]>([]);
  const [errors, setErrors] = useState<{ file: string; error: string; error_en?: string }[]>([]);
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
      notifications.show({ color: "green", message: r.trial ? t("toggle.doneTrial") : t("toggle.done") });
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
      await rulesApi.deletePanelRule(del.id, reason, password);
      notifications.show({ color: "green", message: t("delete.done") });
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
        ruleText(r).title.toLowerCase().includes(needle) ||
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
          <Title order={2}>{t("title")}</Title>
          <Text c="dimmed" size="sm" maw={820}>
            {t("intro")}
          </Text>
        </div>
        {canTest && (
          <Group gap="xs">
            <Button variant="light" leftSection={<IconLink size={16} />} component={Link} to="/rules/correlation">
              {t("newCorrelation")}
            </Button>
            <Button variant="light" leftSection={<IconFlask size={16} />} onClick={() => setTestNew(true)}>
              {t("testNew")}
            </Button>
            <Button variant="light" color="yellow" leftSection={<IconHourglass size={16} />} component={Link} to="/rules/trial">
              {t("trials")}
              {trials > 0 ? ` (${trials})` : ""}
            </Button>
            {admin && (
              <Button variant="subtle" leftSection={<IconDownload size={16} />} onClick={() => setSigmaHelp(true)}>
                {t("sigmaImport")}
              </Button>
            )}
          </Group>
        )}
      </Group>
      {error && <MAlert color="red">{error}</MAlert>}
      {!configured && <MAlert color="gray">{t("notConfigured")}</MAlert>}
      {errors.length > 0 && (
        <MAlert color="red" title={t("fileErrors", { count: errors.length })}>
          {errors.map((e) => (
            <Text size="sm" key={e.file}>
              <Code>{e.file}</Code>: {serverText(e.error, e.error_en)}
            </Text>
          ))}
        </MAlert>
      )}
      {rules.length > 0 && (
        <Group gap="xs" align="flex-end">
          <TextInput
            placeholder={t("filter.search")}
            leftSection={<IconSearch size={14} />}
            value={q}
            onChange={(e) => setQ(e.currentTarget.value)}
            w={320}
          />
          <SegmentedControl
            value={source}
            onChange={setSource}
            data={[
              { value: "all", label: t("filter.source.all") },
              { value: "own", label: t("filter.source.own") },
              { value: "sigmahq", label: "SigmaHQ" },
              { value: "panel", label: t("filter.source.panel") },
              { value: "builtin", label: t("filter.source.builtin") },
            ]}
          />
          <Select
            w={170}
            value={stateF}
            onChange={setStateF}
            allowDeselect={false}
            data={[
              { value: "all", label: t("filter.state.all") },
              { value: "on", label: t("filter.state.on") },
              { value: "off", label: t("filter.state.off") },
              { value: "trial", label: t("filter.state.trial") },
              { value: "panel", label: t("filter.state.panel") },
            ]}
          />
          <MultiSelect
            w={260}
            placeholder={levels.length ? "" : t("filter.anyLevel")}
            value={levels}
            onChange={setLevels}
            clearable
            data={Object.entries(levelLabels).map(([value, l]) => ({ value, label: l.label }))}
          />
          <Text size="sm" c="dimmed">
            {t("filter.count", { shown: filtered.length, total: rules.length })}
          </Text>
        </Group>
      )}
      {admin && selected.size > 0 && (
        <Group gap="xs">
          <Text size="sm" fw={500}>
            {t("selected", { count: selected.size })}
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
            {t("clearSelection")}
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
                      aria-label={t("selectFiltered")}
                      title={t("selectFilteredTitle", { count: filtered.length })}
                    />
                  </Table.Th>
                )}
                <Table.Th>{t("col.enabled")}</Table.Th>
                <Table.Th>{t("col.level")}</Table.Th>
                <Table.Th>{t("col.rule")}</Table.Th>
                <Table.Th>{t("col.engine")}</Table.Th>
                <Table.Th>{t("col.threshold")}</Table.Th>
                <Table.Th>{t("col.openAlerts")}</Table.Th>
                <Table.Th>{t("col.file")}</Table.Th>
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
                        aria-label={t("selectRule")}
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
                        aria-label={t("col.enabled")}
                      />
                      {r.override?.trial && (
                        <Tooltip
                          multiline
                          w={300}
                          label={t("trialTip", {
                            date: formatDate(r.override.changed_at),
                            by: r.override.changed_by,
                            reason: r.override.reason ? ` – ${r.override.reason}` : "",
                          })}
                        >
                          <Badge size="xs" color="yellow" component={Link} to="/rules/trial" style={{ cursor: "pointer" }}>
                            {t("trialBadge")}
                          </Badge>
                        </Tooltip>
                      )}
                      {r.override && !r.override.trial && (
                        <Tooltip
                          multiline
                          w={300}
                          label={t("overrideTip", {
                            by: r.override.changed_by,
                            date: formatDate(r.override.changed_at),
                            reason: r.override.reason ? ` – ${r.override.reason}` : "",
                            file: r.file_enabled ? t("enabledWord") : t("disabledWord"),
                          })}
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
                      {ruleText(r).title}
                    </Text>
                    <Text size="xs" c="dimmed" lineClamp={1}>
                      {ruleText(r).description}
                    </Text>
                    <AttackTags tags={r.tags} size="xs" />
                  </Table.Td>
                  <Table.Td>{modeLabel(r)}</Table.Td>
                  <Table.Td>
                    {r.threshold && (
                      <Text size="xs" fw={500}>
                        {r.threshold.distinct
                          ? t("thresholdDistinct", { count: r.threshold.count, field: r.threshold.distinct, window: fmtDuration(r.threshold.window_s) })
                          : t("threshold", { count: r.threshold.count, window: fmtDuration(r.threshold.window_s) })}
                      </Text>
                    )}
                    {r.group_by.length ? (
                      <Text size="xs">
                        {r.group_by.join(", ")} / {fmtDuration(r.suppress_s)}
                      </Text>
                    ) : r.threshold ? null : (
                      <Text size="xs" c="dimmed">
                        {t("eachEvent")}
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

      <Modal opened={!!show} onClose={() => setShow(null)} title={show && ruleText(show).title} size="xl">
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
              {t("ruleMeta", { id: show.id, version: show.version, date: formatDate(show.loaded_at) })}
            </Text>
            {panelRuleId(show.file) && (
              <Group gap="xs">
                <Badge variant="light" color="grape">
                  {t("panelRule")}
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
                      {t("edit")}
                    </Button>
                    <Button
                      size="xs"
                      variant="light"
                      color="red"
                      leftSection={<IconTrash size={14} />}
                      onClick={() => setDel({ id: panelRuleId(show.file)!, title: ruleText(show).title })}
                    >
                      {t("delete.button")}
                    </Button>
                  </>
                )}
              </Group>
            )}
            <Tabs value={tab} onChange={setTab}>
              <Tabs.List>
                <Tabs.Tab value="source" leftSection={<IconFileCode size={14} />}>
                  {t("tab.source")}
                </Tabs.Tab>
                <Tabs.Tab value="versions" leftSection={<IconHistory size={14} />}>
                  {t("tab.versions")}
                </Tabs.Tab>
                {canTest && show.mode !== "system" && !(show.mode === "correlation" && show.file === "(wbudowana)") && (
                  <Tabs.Tab value="test" leftSection={<IconFlask size={14} />}>
                    {t("tab.test")}
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

      <Modal opened={!!del} onClose={() => setDel(null)} title={del ? t("delete.title", { title: del.title }) : ""} centered>
        {del && (
          <Stack>
            <MAlert color="orange">
              {t("delete.warning")}
            </MAlert>
            <Textarea label={t("reason")} autosize minRows={2} value={reason} onChange={(e) => setReason(e.currentTarget.value)} />
            <PasswordInput label={t("yourPassword")} value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
            <Group justify="flex-end">
              <Button color="red" loading={busy} disabled={reason.trim().length < 3 || !password} onClick={() => void applyDelete()}>
                {t("delete.confirm")}
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>

      <Modal opened={sigmaHelp} onClose={() => setSigmaHelp(false)} title={t("sigmaImport")} size="xl">
        {sigmaHelp && <SigmaImportHelp />}
      </Modal>

      <Modal opened={testNew} onClose={() => setTestNew(false)} title={t("testNewTitle")} size="xl">
        {testNew && <RuleTester initial={newRuleTemplate()} />}
      </Modal>

      <Modal
        opened={!!toggle}
        onClose={() => {
          setToggle(null);
          setNeedPassword(false);
        }}
        title={
          toggle
            ? t(toggle.trial ? "toggle.titleTrial" : disabling ? "toggle.titleDisable" : "toggle.titleEnable", { title: ruleText(toggle.rule).title })
            : ""
        }
        centered
      >
        {toggle && (
          <Stack>
            {toggle.trial && (
              <MAlert color="yellow">
                {t("toggle.trialInfo")}
              </MAlert>
            )}
            {disabling && (
              <MAlert color="orange">
                {toggle.trial ? t("toggle.trialWarning") : t("toggle.disableWarning")}
              </MAlert>
            )}
            {!toggle.trial && toggle.enabled && trialCapable(toggle.rule) && !toggle.rule.override?.trial && (
              <Button size="xs" variant="light" color="yellow" leftSection={<IconHourglass size={14} />}
                onClick={() => setToggle({ ...toggle, trial: true })}>
                {t("toggle.trialFirst")}
              </Button>
            )}
            <Textarea
              label={t("reason")}
              description={disabling ? t("toggle.reasonHint") : t("optional")}
              autosize
              minRows={2}
              value={reason}
              onChange={(e) => setReason(e.currentTarget.value)}
            />
            {(needPassword || disabling) && (
              <PasswordInput label={t("yourPassword")} value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
            )}
            <Group justify="space-between">
              {toggle.rule.override ? (
                <Button
                  variant="subtle"
                  size="xs"
                  onClick={() => setToggle({ rule: toggle.rule, enabled: null })}
                  disabled={toggle.enabled === null}
                >
                  {t("toggle.backToFile", { state: toggle.rule.file_enabled ? t("enabledWord") : t("disabledWord") })}
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
                  ? t("toggle.restore")
                  : toggle.trial
                    ? t("toggle.startTrial")
                    : disabling
                      ? t("toggle.disable")
                      : t("toggle.enable")}
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
