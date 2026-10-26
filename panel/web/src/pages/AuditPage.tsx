// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import { Alert, Badge, Button, Code, Group, Stack, Table, Text, Title } from "@mantine/core";
import { useTranslation } from "react-i18next";
import { api, formatDate, type AuditEntry } from "../api";

// Kolory akcji z dziennika; czytelne nazwy – admin: audit.action.<akcja>
// (pozostałe akcje pokazywane kodem).
const actionColors: Record<string, string> = {
  login: "green",
  login_failed: "orange",
  logout: "gray",
  password_changed: "blue",
  password_change_failed: "orange",
  password_reset: "violet",
  user_created: "teal",
  user_updated: "indigo",
  api_token_created: "teal",
  api_token_revoked: "gray",
  api_token_denied: "red",
};

export default function AuditPage() {
  const { t } = useTranslation("admin");
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [more, setMore] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback((before?: number) => {
    api
      .audit(before)
      .then((r) => {
        setEntries((prev) => (before ? [...prev, ...r.entries] : r.entries));
        setMore(r.entries.length === 100);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);
  useEffect(() => load(), [load]);

  return (
    <Stack>
      <div>
        <Title order={2}>{t("audit.title")}</Title>
        <Text c="dimmed" size="sm">
          {t("audit.intro")}
        </Text>
      </div>
      {error && <Alert color="red">{error}</Alert>}
      <Table.ScrollContainer minWidth={760}>
        <Table striped verticalSpacing="xs">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t("audit.col.time")}</Table.Th>
              <Table.Th>{t("audit.col.user")}</Table.Th>
              <Table.Th>{t("audit.col.action")}</Table.Th>
              <Table.Th>{t("audit.col.target")}</Table.Th>
              <Table.Th>{t("audit.col.ip")}</Table.Th>
              <Table.Th>{t("audit.col.details")}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {entries.map((e) => {
              const a = { label: t(`audit.action.${e.action}`, { defaultValue: e.action }), color: actionColors[e.action] ?? "gray" };
              return (
                <Table.Tr key={e.id}>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>
                    <Text size="sm">{formatDate(e.at)}</Text>
                  </Table.Td>
                  <Table.Td>{e.username || "—"}</Table.Td>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>
                    <Badge color={a.color} variant="light" styles={{ label: { overflow: "visible" } }}>
                      {a.label}
                    </Badge>
                  </Table.Td>
                  <Table.Td>{e.target || "—"}</Table.Td>
                  <Table.Td>
                    <Text size="sm" ff="monospace">
                      {e.ip || "—"}
                    </Text>
                  </Table.Td>
                  <Table.Td>{e.details ? <Code>{JSON.stringify(e.details)}</Code> : "—"}</Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      {more && entries.length > 0 && (
        <Group>
          <Button variant="default" onClick={() => load(entries[entries.length - 1].id)}>
            {t("audit.older")}
          </Button>
        </Group>
      )}
    </Stack>
  );
}
