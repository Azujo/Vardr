import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Anchor,
  Badge,
  Button,
  Card,
  CopyButton,
  Group,
  MultiSelect,
  SimpleGrid,
  Stack,
  Table,
  TagsInput,
  Text,
  TextInput,
  Textarea,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconDownload, IconFileExport } from "@tabler/icons-react";
import {
  agentsApi,
  exportStatusLabels,
  exportsApi,
  formatBytes,
  formatDate,
  formatNumber,
  groupsApi,
  type AgentGroup,
  type AgentView,
  type ArchiveExport,
} from "../api";

// Wartość dla <input type="datetime-local"> (czas lokalny, pełna godzina).
function localHour(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:00`;
}

function hourRange(from: string, to: string) {
  const opt: Intl.DateTimeFormatOptions = { dateStyle: "short", timeStyle: "short" };
  return `${new Date(from).toLocaleString("pl-PL", opt)} – ${new Date(to).toLocaleString("pl-PL", opt)}`;
}

// Eksport dla audytora (tylko administrator): zlecenie, stan i pobranie paczki.
export default function ArchiveExports() {
  const [from, setFrom] = useState(() => localHour(new Date(Date.now() - 24 * 3600_000)));
  const [to, setTo] = useState(() => localHour(new Date()));
  const [reason, setReason] = useState("");
  const [selGroups, setSelGroups] = useState<string[]>([]);
  const [selAgents, setSelAgents] = useState<string[]>([]);
  const [groups, setGroups] = useState<AgentGroup[]>([]);
  const [agents, setAgents] = useState<AgentView[]>([]);
  const [busy, setBusy] = useState(false);
  const [items, setItems] = useState<ArchiveExport[]>([]);
  const [downloads, setDownloads] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    exportsApi
      .list()
      .then((r) => {
        setItems(r.exports);
        setDownloads(r.downloads);
        setError("");
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);
  useEffect(() => {
    groupsApi
      .list()
      .then((r) => setGroups(r.groups))
      .catch(() => {});
    agentsApi
      .list()
      .then((r) => setAgents(r.agents))
      .catch(() => {});
  }, []);
  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await exportsApi.create({
        from: new Date(from).toISOString(),
        to: new Date(to).toISOString(),
        reason,
        agents: selAgents,
        groups: selGroups.map(Number),
      });
      notifications.show({ color: "green", message: "Eksport zlecony – archiwizator przygotuje paczkę w ciągu kilkunastu sekund." });
      setReason("");
      load();
    } catch (err) {
      notifications.show({ color: "red", message: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack>
      <Card withBorder>
        <form onSubmit={submit}>
          <Stack gap="sm">
            <Group gap="xs">
              <IconFileExport size={20} />
              <Title order={4}>Eksport dla audytora</Title>
            </Group>
            <Text size="sm" c="dimmed">
              Paczka (.tar) do przekazania np. audytorowi, CSIRT albo organowi nadzoru – czytelna bez Heimdalla: zdarzenia
              z wybranych godzin jako NDJSON (pola ECS + oryginalny XML) i CSV, a jako dowód oryginalne segmenty, łańcuch
              manifestów i sumy SHA-256. Odbiorca uruchamia dołączony <code>odczytaj.exe</code> (sprawdzenie + czytelny
              RAPORT.txt i pliki dzienne ze zdarzeniami) albo skrypt w Pythonie <code>narzedzia/odczytaj_segmenty.py</code>.
              Zlecenie i każde pobranie trafiają do dziennika audytu.
            </Text>
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <TextInput
                type="datetime-local"
                label="Od (pełna godzina)"
                required
                value={from}
                onChange={(e) => setFrom(e.currentTarget.value)}
              />
              <TextInput
                type="datetime-local"
                label="Do (pełna godzina, bez niej)"
                required
                value={to}
                onChange={(e) => setTo(e.currentTarget.value)}
              />
            </SimpleGrid>
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <MultiSelect
                label="Tylko grupy agentów (opcjonalnie)"
                data={groups.map((g) => ({ value: String(g.id), label: `${g.name} (${g.agents} agentów)` }))}
                value={selGroups}
                onChange={setSelGroups}
                searchable
                clearable
              />
              <TagsInput
                label="Tylko agenci (opcjonalnie)"
                data={agents.map((a) => ({ value: a.id, label: `${a.id} (${a.hostname})` }))}
                value={selAgents}
                onChange={setSelAgents}
                clearable
              />
            </SimpleGrid>
            <Text size="xs" c="dimmed">
              Bez wyboru – wszystkie źródła. Wybór ogranicza część czytelną (zdarzenia, raport odczytaj.exe); dowód (segmenty)
              zawiera wszystkie paczki z wybranych godzin, bo tylko cały segment można sprawdzić względem manifestu.
            </Text>
            <Textarea
              label="Powód eksportu"
              description="np. numer kontroli lub zgłoszenia – trafi do audytu i do paczki"
              required
              minLength={5}
              maxLength={1000}
              autosize
              minRows={2}
              value={reason}
              onChange={(e) => setReason(e.currentTarget.value)}
            />
            <Group>
              <Button type="submit" loading={busy} leftSection={<IconFileExport size={18} />}>
                Zleć eksport
              </Button>
            </Group>
          </Stack>
        </form>
      </Card>

      {error && <Alert color="red">{error}</Alert>}
      {!downloads && (
        <Alert color="orange">
          Pobieranie paczek jest wyłączone – siem-api nie ma dostępu do katalogu eksportów (SIEM_ARCHIVE_EXPORT_DIR).
        </Alert>
      )}
      {items.length > 0 && (
        <Table.ScrollContainer minWidth={900}>
          <Table striped verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr style={{ whiteSpace: "nowrap" }}>
                <Table.Th>Nr</Table.Th>
                <Table.Th>Zakres</Table.Th>
                <Table.Th>Zlecił / powód</Table.Th>
                <Table.Th>Stan</Table.Th>
                <Table.Th>Zawartość</Table.Th>
                <Table.Th>SHA-256 paczki</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((x) => (
                <Table.Tr key={x.id}>
                  <Table.Td>{x.id}</Table.Td>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>{hourRange(x.from, x.to)}</Table.Td>
                  <Table.Td maw={260}>
                    <Text size="sm">{x.requested_by}</Text>
                    <Text size="xs" c="dimmed" lineClamp={2} title={x.reason}>
                      {x.reason}
                    </Text>
                    {x.agents?.length > 0 && (
                      <Text size="xs" c="dimmed" lineClamp={1} title={x.agents.join(", ")}>
                        agenci: {x.agents.join(", ")}
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    <Tooltip label={x.error || formatDate(x.finished_at ?? x.requested_at)} multiline maw={400}>
                      <Badge color={exportStatusLabels[x.status].color} variant="light">
                        {exportStatusLabels[x.status].label}
                      </Badge>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>
                    {x.status === "done" || x.status === "expired" ? (
                      <Text size="sm">
                        {x.manifests} h, {formatNumber(x.records)} paczek, {formatBytes(x.bytes)}
                      </Text>
                    ) : (
                      <Text size="sm" c="dimmed">
                        —
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    {x.sha256 ? (
                      <CopyButton value={x.sha256}>
                        {({ copied, copy }) => (
                          <Tooltip label={copied ? "skopiowano" : x.sha256} multiline maw={600}>
                            <Text size="xs" ff="monospace" c="dimmed" style={{ cursor: "pointer" }} onClick={copy}>
                              {x.sha256?.slice(0, 16)}…
                            </Text>
                          </Tooltip>
                        )}
                      </CopyButton>
                    ) : (
                      "—"
                    )}
                  </Table.Td>
                  <Table.Td>
                    {x.status === "done" && downloads && (
                      <Anchor href={exportsApi.downloadUrl(x.id)} size="sm">
                        <Group gap={4} wrap="nowrap">
                          <IconDownload size={16} /> pobierz
                        </Group>
                      </Anchor>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Stack>
  );
}
