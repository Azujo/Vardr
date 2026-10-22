// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import { Alert, Badge, Button, Code, Group, Stack, Table, Text, Title } from "@mantine/core";
import { api, formatDate, type AuditEntry } from "../api";

// Czytelne nazwy akcji z dziennika.
const actionLabels: Record<string, { label: string; color: string }> = {
  login: { label: "logowanie", color: "green" },
  login_failed: { label: "nieudane logowanie", color: "orange" },
  logout: { label: "wylogowanie", color: "gray" },
  password_changed: { label: "zmiana hasła", color: "blue" },
  password_change_failed: { label: "nieudana zmiana hasła", color: "orange" },
  password_reset: { label: "nowe hasło startowe", color: "violet" },
  user_created: { label: "nowe konto", color: "teal" },
  user_updated: { label: "zmiana konta", color: "indigo" },
};

export default function AuditPage() {
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
        <Title order={2}>Dziennik audytu</Title>
        <Text c="dimmed" size="sm">
          Logowania i zmiany w panelu – kto, kiedy, skąd i co zmienił.
        </Text>
      </div>
      {error && <Alert color="red">{error}</Alert>}
      <Table.ScrollContainer minWidth={760}>
        <Table striped verticalSpacing="xs">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Czas</Table.Th>
              <Table.Th>Użytkownik</Table.Th>
              <Table.Th>Akcja</Table.Th>
              <Table.Th>Dotyczy</Table.Th>
              <Table.Th>Adres IP</Table.Th>
              <Table.Th>Szczegóły</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {entries.map((e) => {
              const a = actionLabels[e.action] ?? { label: e.action, color: "gray" };
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
            Starsze wpisy
          </Button>
        </Group>
      )}
    </Stack>
  );
}
