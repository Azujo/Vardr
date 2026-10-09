import { useEffect, useState } from "react";
import { Alert as MAlert, Anchor, Badge, Code, Group, Modal, ScrollArea, Stack, Table, Text, Title } from "@mantine/core";
import { Link } from "react-router-dom";
import { alertsApi, formatDate, levelLabels, type RuleInfo } from "../api";

const modeLabels: Record<string, string> = { stream: "w locie", index_query: "zapytania", both: "oba silniki" };

// Reguły detekcji wczytane przez detektor (pliki YAML z katalogu rules/).
export default function RulesPage() {
  const [rules, setRules] = useState<RuleInfo[]>([]);
  const [errors, setErrors] = useState<{ file: string; error: string }[]>([]);
  const [configured, setConfigured] = useState(true);
  const [error, setError] = useState("");
  const [show, setShow] = useState<RuleInfo | null>(null);

  useEffect(() => {
    alertsApi
      .rules()
      .then((r) => {
        setRules(r.rules);
        setErrors(r.errors);
        setConfigured(r.configured);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  return (
    <Stack>
      <div>
        <Title order={2}>Reguły detekcji</Title>
        <Text c="dimmed" size="sm" maw={820}>
          Reguły w formacie Sigma (YAML) z katalogu <Code>rules/</Code> w repozytorium – wdrażane poleceniem{" "}
          <Code>deploy.sh rules</Code>, detektor przeładowuje je w ciągu 30 s. Edycja i testowanie reguł w panelu – etap 5.
        </Text>
      </div>
      {error && <MAlert color="red">{error}</MAlert>}
      {!configured && <MAlert color="gray">Detektor (siem-detector) jeszcze nie działał.</MAlert>}
      {errors.length > 0 && (
        <MAlert color="red" title={`Reguły odrzucone (${errors.length})`}>
          {errors.map((e) => (
            <Text size="sm" key={e.file}>
              <Code>{e.file}</Code>: {e.error}
            </Text>
          ))}
        </MAlert>
      )}
      {rules.length > 0 && (
        <Table.ScrollContainer minWidth={900}>
          <Table striped highlightOnHover verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Poziom</Table.Th>
                <Table.Th>Reguła</Table.Th>
                <Table.Th>Silnik</Table.Th>
                <Table.Th>Łączenie</Table.Th>
                <Table.Th>Otwarte alerty</Table.Th>
                <Table.Th>Plik</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {rules.map((r) => (
                <Table.Tr key={r.id} style={{ cursor: "pointer", opacity: r.enabled ? 1 : 0.5 }} onClick={() => setShow(r)}>
                  <Table.Td>
                    <Badge color={levelLabels[r.level].color}>{levelLabels[r.level].label}</Badge>
                  </Table.Td>
                  <Table.Td maw={420}>
                    <Text size="sm" fw={500}>
                      {r.title} {!r.enabled && <Badge size="xs" color="gray">wyłączona</Badge>}
                    </Text>
                    <Text size="xs" c="dimmed" lineClamp={1}>
                      {r.description}
                    </Text>
                  </Table.Td>
                  <Table.Td>{modeLabels[r.mode] ?? r.mode}</Table.Td>
                  <Table.Td>
                    {r.group_by.length ? (
                      <Text size="xs">
                        {r.group_by.join(", ")} / {Math.round(r.suppress_s / 60)} min
                      </Text>
                    ) : (
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
                      {r.file}
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
              id {show.id} · wczytana {formatDate(show.loaded_at)}
            </Text>
            <ScrollArea.Autosize mah={500}>
              <Code block>{show.source}</Code>
            </ScrollArea.Autosize>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
