// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState, type ReactNode } from "react";
import { Alert as MAlert, Button, Code, Group, Select, Stack, Table, Text, Textarea } from "@mantine/core";
import { IconFlask } from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import { formatDate, rulesApi, type RuleTestResult } from "../api";
import { locale, serverText } from "../i18n";

// Test reguły na zdarzeniach z ostatnich godzin (bez wdrażania).
export default function RuleTester({
  initial,
  onChange,
  note,
}: {
  initial: string;
  onChange?: (source: string) => void;
  note?: ReactNode;
}) {
  const { t } = useTranslation("rules");
  const [source, setSourceState] = useState(initial);
  const setSource = (v: string) => {
    setSourceState(v);
    onChange?.(v);
  };
  const [hours, setHours] = useState("24");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [res, setRes] = useState<RuleTestResult | null>(null);
  const [sql, setSql] = useState("");
  const [warnings, setWarnings] = useState<string[]>([]);
  useEffect(() => setSourceState(initial), [initial]);

  const run = async () => {
    setBusy(true);
    setErr("");
    setRes(null);
    try {
      const r = await rulesApi.test(source, Number(hours));
      if (!r.ok) setErr(r.error ? serverText(r.error, r.error_en) : t("tester.error"));
      else {
        // Puste listy mogą przyjść jako null (starszy serwer) – bez tego strona się wywracała.
        setRes(r.result ? { ...r.result, events: r.result.events ?? [], alerts: r.result.alerts ?? [] } : null);
        setSql(r.sql ?? "");
        setWarnings((locale() !== "pl" && r.attack_warnings_en) || r.attack_warnings || []);
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack gap="xs">
      {note ?? (
        <Text size="xs" c="dimmed">
          {t("tester.intro")} (<Code>deploy.sh rules</Code>).
        </Text>
      )}
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
            { value: "1", label: t("tester.range.1") },
            { value: "24", label: t("tester.range.24") },
            { value: "72", label: t("tester.range.72") },
            { value: "168", label: t("tester.range.168") },
          ]}
        />
        <Button leftSection={<IconFlask size={16} />} loading={busy} onClick={() => void run()}>
          {t("tester.run")}
        </Button>
      </Group>
      {err && (
        <MAlert color="red" title={t("tester.failed")}>
          <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>
            {err}
          </Text>
        </MAlert>
      )}
      {res && warnings.length > 0 && (
        <MAlert color="orange" title={t("tester.attackTags")}>
          {warnings.map((w) => (
            <Text size="sm" key={w}>
              {w}
            </Text>
          ))}
        </MAlert>
      )}
      {res && (
        <Stack gap="xs">
          <MAlert color={res.alerts_total > 0 ? "orange" : "green"}>
            <Text size="sm">
              {t("tester.matched")} <b>{res.matched}</b> · {t("tester.alerts")} <b>{res.alerts_total}</b>
              {res.truncated ? t("tester.truncated") : ""} · {res.took_ms} ms
            </Text>
          </MAlert>
          {res.alerts.length > 0 && (
            <Table fz="xs" verticalSpacing={2} withTableBorder>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t("tester.colKey")}</Table.Th>
                  <Table.Th>{t("tester.colEvents")}</Table.Th>
                  <Table.Th>{t("tester.colFrom")}</Table.Th>
                  <Table.Th>{t("tester.colTo")}</Table.Th>
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
                {t("tester.lastEvents")}
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
                  {t("tester.sql")}
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
