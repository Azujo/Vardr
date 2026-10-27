// SPDX-License-Identifier: AGPL-3.0-or-later

// Wyjątki reguł (wersja 1.5.3): warunek, przy którym reguła nie trafia –
// typowo powtarzalny fałszywy alarm. Lista na stronie reguły i edytor
// (także z alertu – pola zdarzenia do wyboru – i z propozycji asystenta AI).

import { useCallback, useEffect, useState } from "react";
import {
  ActionIcon,
  Alert as MAlert,
  Badge,
  Button,
  Code,
  Group,
  Modal,
  PasswordInput,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Textarea,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconPlus, IconSearch, IconSparkles, IconTrash, IconX } from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import { aiApi, formatDate, rulesApi, type ExceptionMatch, type RuleException, type RuleTestResult } from "../api";
import { serverText } from "../i18n";
import { useAuth } from "../auth";

// Pseudonimy z maskowania danych dla AI (USER-…, HOST-…) – w wyjątku muszą
// być prawdziwe wartości; odkrycie wymaga uprawnienia i trafia do audytu.
const pseudonymRe = /\b(?:USER|HOST|IP|EMAIL)-[0-9A-F]{8}\b/g;

const modifiers = ["", "contains", "startswith", "endswith", "re", "cidr"];

interface Row {
  field: string;
  mod: string;
  value: string;
}

// Wiersze edytora → warunek; ten sam klucz kilka razy = lista (którakolwiek wartość).
export function rowsToMatch(rows: Row[]): ExceptionMatch {
  const m: Record<string, string[]> = {};
  for (const r of rows) {
    const f = r.field.trim();
    if (!f) continue;
    const k = r.mod ? `${f}|${r.mod}` : f;
    (m[k] ??= []).push(r.value);
  }
  return Object.fromEntries(Object.entries(m).map(([k, v]) => [k, v.length === 1 ? v[0] : v]));
}

export function matchToRows(m: ExceptionMatch): Row[] {
  const out: Row[] = [];
  for (const [k, v] of Object.entries(m)) {
    const [field, mod = ""] = k.split("|");
    for (const x of Array.isArray(v) ? v : [v]) out.push({ field, mod, value: String(x) });
  }
  return out;
}

// Warunek jako tekst (lista wyjątków).
export function matchText(m: ExceptionMatch): string {
  return Object.entries(m)
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? `[${v.join(", ")}]` : String(v)}`)
    .join(" · ");
}

export interface ExceptionDraft {
  match?: ExceptionMatch;
  reason?: string;
  aiProposed?: boolean;
}

// Edytor wyjątku: warunek, sprawdzenie na historii (7 dni), powód,
// wygaśnięcie i hasło. candidates – pola zdarzenia alertu do wstawienia.
export function ExceptionModal({
  ruleId,
  ruleTitle,
  opened,
  onClose,
  onSaved,
  draft,
  candidates,
}: {
  ruleId: string;
  ruleTitle?: string;
  opened: boolean;
  onClose: () => void;
  onSaved?: () => void;
  draft?: ExceptionDraft;
  candidates?: Record<string, string>;
}) {
  const { t } = useTranslation("rules");
  const [rows, setRows] = useState<Row[]>([]);
  const [reason, setReason] = useState("");
  const [days, setDays] = useState("90");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [check, setCheck] = useState<{ suppressed: number; alerts: number; days: number; events: RuleTestResult["events"] } | null>(null);
  const [checkErr, setCheckErr] = useState("");
  const { can } = useAuth();

  useEffect(() => {
    if (!opened) return;
    setRows(draft?.match ? matchToRows(draft.match) : [{ field: "", mod: "", value: "" }]);
    setReason(draft?.reason ?? "");
    setDays("90");
    setPassword("");
    setCheck(null);
    setCheckErr("");
  }, [opened, draft]);

  const match = rowsToMatch(rows);
  const pseudonyms = [...new Set(rows.flatMap((r) => r.value.match(pseudonymRe) ?? []))];
  const reveal = async () => {
    setBusy(true);
    try {
      const values: Record<string, string> = {};
      for (const p of pseudonyms) values[p] = (await aiApi.reveal(p, t("exceptions.revealReason", { rule: ruleId }))).pseudonym.value;
      setRows((rs) => rs.map((r) => ({ ...r, value: r.value.replace(pseudonymRe, (p) => values[p] ?? p) })));
      setCheck(null);
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };
  const valid = Object.keys(match).length > 0 && rows.every((r) => !r.field.trim() || r.value !== "") && pseudonyms.length === 0;
  const setRow = (i: number, p: Partial<Row>) => {
    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, ...p } : r)));
    setCheck(null);
  };

  const runCheck = async () => {
    setBusy(true);
    setCheckErr("");
    try {
      const r = await rulesApi.checkException(ruleId, match);
      if (!r.ok) setCheckErr(serverText(r.error ?? "", r.error_en));
      else setCheck({ suppressed: r.suppressed ?? 0, alerts: r.alerts ?? 0, days: r.days ?? 7, events: r.events ?? [] });
    } catch (e) {
      setCheckErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const save = async () => {
    setBusy(true);
    try {
      const r = await rulesApi.addException(ruleId, match, reason.trim(), Number(days), password, !!draft?.aiProposed);
      notifications.show({ color: "green", message: r.message });
      onSaved?.();
      onClose();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  const cand = candidates
    ? Object.entries(candidates)
        .filter(([, v]) => v !== "")
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => ({ value: k, label: `${k} = ${v.length > 60 ? v.slice(0, 60) + "…" : v}` }))
    : [];

  return (
    <Modal opened={opened} onClose={onClose} size="xl" title={t("exceptions.addTitle", { title: ruleTitle ?? ruleId })}>
      <Stack>
        <Text size="sm" c="dimmed">
          {t("exceptions.help")}
        </Text>
        {draft?.aiProposed && (
          <MAlert color="violet" icon={<IconSparkles size={16} />}>
            {t("exceptions.aiDraft")}
          </MAlert>
        )}
        {pseudonyms.length > 0 && (
          <MAlert color="orange">
            <Text size="sm">{t("exceptions.pseudonyms", { list: pseudonyms.join(", ") })}</Text>
            {can("ai", "reveal") && (
              <Button mt="xs" size="xs" variant="light" loading={busy} onClick={() => void reveal()}>
                {t("exceptions.reveal")}
              </Button>
            )}
          </MAlert>
        )}
        {cand.length > 0 && (
          <Select
            searchable
            placeholder={t("exceptions.fromEvent")}
            data={cand}
            value={null}
            onChange={(k) => {
              if (!k) return;
              setRows((rs) => [...rs.filter((r) => r.field.trim()), { field: k, mod: "", value: candidates![k] }]);
              setCheck(null);
            }}
          />
        )}
        {rows.map((r, i) => (
          <Group key={i} gap="xs" wrap="nowrap" align="flex-end">
            <TextInput
              style={{ flex: 2 }}
              label={i === 0 ? t("exceptions.field") : undefined}
              value={r.field}
              onChange={(e) => setRow(i, { field: e.currentTarget.value })}
            />
            <Select
              w={140}
              label={i === 0 ? t("exceptions.modifier") : undefined}
              data={modifiers.map((m) => ({ value: m, label: m || t("exceptions.equals") }))}
              value={r.mod}
              onChange={(v) => setRow(i, { mod: v ?? "" })}
              allowDeselect={false}
            />
            <TextInput
              style={{ flex: 3 }}
              label={i === 0 ? t("exceptions.value") : undefined}
              value={r.value}
              onChange={(e) => setRow(i, { value: e.currentTarget.value })}
            />
            <ActionIcon variant="subtle" color="gray" mb={4} aria-label={t("exceptions.removeRow")}
              onClick={() => setRows((rs) => rs.filter((_, j) => j !== i))}>
              <IconX size={16} />
            </ActionIcon>
          </Group>
        ))}
        <Group>
          <Button size="xs" variant="subtle" leftSection={<IconPlus size={14} />}
            onClick={() => setRows((rs) => [...rs, { field: "", mod: "", value: "" }])}>
            {t("exceptions.addRow")}
          </Button>
          <Button size="xs" variant="light" leftSection={<IconSearch size={14} />} loading={busy} disabled={!valid}
            onClick={() => void runCheck()}>
            {t("exceptions.check")}
          </Button>
        </Group>
        {checkErr && <MAlert color="red">{checkErr}</MAlert>}
        {check && (
          <MAlert color={check.suppressed === 0 ? "gray" : "orange"}>
            <Text size="sm">{t("exceptions.checkResult", { count: check.suppressed, days: check.days, alerts: check.alerts })}</Text>
            {check.events.length > 0 && (
              <Table mt="xs" fz="xs" verticalSpacing={2}>
                <Table.Tbody>
                  {check.events.slice(0, 10).map((e) => (
                    <Table.Tr key={e.event_id}>
                      <Table.Td>{formatDate(e.timestamp)}</Table.Td>
                      <Table.Td>{e.host}</Table.Td>
                      <Table.Td>{e.user}</Table.Td>
                      <Table.Td>{e.summary}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}
          </MAlert>
        )}
        <Textarea label={t("exceptions.reason")} placeholder={t("exceptions.reasonPlaceholder")} autosize minRows={2}
          value={reason} onChange={(e) => setReason(e.currentTarget.value)} />
        <Group grow>
          <Select
            label={t("exceptions.expires")}
            data={[
              { value: "7", label: t("exceptions.days", { count: 7 }) },
              { value: "30", label: t("exceptions.days", { count: 30 }) },
              { value: "90", label: t("exceptions.days", { count: 90 }) },
              { value: "365", label: t("exceptions.days", { count: 365 }) },
              { value: "0", label: t("exceptions.never") },
            ]}
            value={days}
            onChange={(v) => setDays(v ?? "90")}
            allowDeselect={false}
          />
          <PasswordInput label={t("yourPassword")} value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
        </Group>
        <Group justify="flex-end">
          <Button loading={busy} disabled={!valid || reason.trim().length < 3 || !password} onClick={() => void save()}>
            {t("exceptions.save")}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

// Lista wyjątków reguły (zakładka w szczegółach reguły).
export function RuleExceptions({ ruleId, ruleTitle, canWrite }: { ruleId: string; ruleTitle: string; canWrite: boolean }) {
  const { t } = useTranslation("rules");
  const [list, setList] = useState<RuleException[] | null>(null);
  const [err, setErr] = useState("");
  const [adding, setAdding] = useState(false);
  const load = useCallback(() => {
    rulesApi
      .exceptions(ruleId)
      .then((r) => setList(r.exceptions))
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, [ruleId]);
  useEffect(() => load(), [load]);

  const remove = async (e: RuleException) => {
    if (!window.confirm(t("exceptions.deleteConfirm"))) return;
    try {
      const r = await rulesApi.deleteException(ruleId, e.id);
      notifications.show({ color: "green", message: r.message });
      load();
    } catch (x) {
      notifications.show({ color: "red", message: x instanceof Error ? x.message : String(x) });
    }
  };

  if (err) return <Text size="sm" c="red">{err}</Text>;
  if (!list) return <Text size="sm" c="dimmed">{t("common:loading")}</Text>;
  const now = Date.now();
  return (
    <Stack gap="xs">
      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          {t("exceptions.intro")}
        </Text>
        {canWrite && (
          <Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={() => setAdding(true)}>
            {t("exceptions.add")}
          </Button>
        )}
      </Group>
      {list.length === 0 ? (
        <Text size="sm">{t("exceptions.none")}</Text>
      ) : (
        <Table fz="sm" verticalSpacing={4}>
          <Table.Tbody>
            {list.map((e) => {
              const expired = !!e.expires_at && new Date(e.expires_at).getTime() <= now;
              return (
                <Table.Tr key={e.id} style={expired ? { opacity: 0.55 } : undefined}>
                  <Table.Td>
                    <Code>{matchText(e.match)}</Code>
                    <Text size="xs" mt={2}>
                      {e.reason}
                    </Text>
                    <Text size="xs" c="dimmed">
                      {t("exceptions.meta", { by: e.created_by, date: formatDate(e.created_at) })}
                      {" · "}
                      {e.expires_at
                        ? t(expired ? "exceptions.expired" : "exceptions.expiresAt", { date: formatDate(e.expires_at) })
                        : t("exceptions.noExpiry")}
                    </Text>
                  </Table.Td>
                  <Table.Td w={90}>
                    {e.ai_proposed && (
                      <Badge size="xs" variant="light" color="violet">
                        {t("exceptions.ai")}
                      </Badge>
                    )}
                  </Table.Td>
                  <Table.Td w={40}>
                    {canWrite && (
                      <ActionIcon variant="subtle" color="red" aria-label={t("exceptions.delete")} onClick={() => void remove(e)}>
                        <IconTrash size={16} />
                      </ActionIcon>
                    )}
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      )}
      <ExceptionModal ruleId={ruleId} ruleTitle={ruleTitle} opened={adding} onClose={() => setAdding(false)} onSaved={load} />
    </Stack>
  );
}
