import { useCallback, useEffect, useState } from "react";
import { Alert, Anchor, Badge, Button, Card, Group, SimpleGrid, Stack, Table, Text, TextInput, Textarea, Title, Tooltip } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconHistory } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { formatBytes, formatDate, formatNumber, replayStatusLabels, replaysApi, type ArchiveReplay } from "../api";

function localHour(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:00`;
}

function hourRange(from: string, to: string) {
  const opt: Intl.DateTimeFormatOptions = { dateStyle: "short", timeStyle: "short" };
  return `${new Date(from).toLocaleString("pl-PL", opt)} – ${new Date(to).toLocaleString("pl-PL", opt)}`;
}

// Link do Mímira: dane odtworzone z archiwum, zakres zlecenia (czas zdarzeń
// z dnia zapasem – paczki mogły czekać u agenta przed wysłaniem).
function mimirLink(x: ArchiveReplay) {
  const from = new Date(new Date(x.from).getTime() - 24 * 3600_000).toISOString().replace(/\.\d+Z$/, "Z");
  const to = new Date(x.to).toISOString().replace(/\.\d+Z$/, "Z");
  const p = new URLSearchParams({ source: "replay", range: "custom", from, to });
  if (x.agents.length === 1) p.set("q", `agent:${x.agents[0]}`);
  return `/events?${p.toString()}`;
}

// Odtworzenie z archiwum (tylko administrator): paczki z wybranych godzin
// trafiają przez osobną ścieżkę do tabeli siem.events_replay.
export default function ArchiveReplays() {
  const [from, setFrom] = useState(() => localHour(new Date(Date.now() - 24 * 3600_000)));
  const [to, setTo] = useState(() => localHour(new Date()));
  const [agents, setAgents] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [items, setItems] = useState<ArchiveReplay[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    replaysApi
      .list()
      .then((r) => {
        setItems(r.replays);
        setError("");
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);
  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [load]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await replaysApi.create({
        from: new Date(from).toISOString(),
        to: new Date(to).toISOString(),
        agents: agents
          .split(/[\s,;]+/)
          .map((a) => a.trim())
          .filter(Boolean),
        reason,
      });
      notifications.show({ color: "green", message: "Odtworzenie zlecone – archiwizator rozpocznie je w ciągu kilkunastu sekund." });
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
              <IconHistory size={20} />
              <Title order={4}>Odtworzenie z archiwum</Title>
            </Group>
            <Text size="sm" c="dimmed">
              Oryginalne paczki z wybranych godzin archiwizacji przechodzą ponownie przez normalizację – osobną ścieżką, do
              osobnej tabeli. Odtworzone zdarzenia widać w Mímirze po przełączeniu na „Odtworzone z archiwum”; nie mieszają
              się z bieżącymi i nie trafią do detekcji. Przydatne np. do analizy danych starszych niż retencja bazy zdarzeń.
              Zlecenie trafia do dziennika audytu.
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
            <TextInput
              label="Agenci (opcjonalnie)"
              description="identyfikatory agentów oddzielone przecinkami; puste = wszyscy"
              placeholder="np. agt-dc01, agt-iis01"
              value={agents}
              onChange={(e) => setAgents(e.currentTarget.value)}
            />
            <Textarea
              label="Powód odtworzenia"
              description="np. numer incydentu – trafi do audytu"
              required
              minLength={5}
              maxLength={1000}
              autosize
              minRows={2}
              value={reason}
              onChange={(e) => setReason(e.currentTarget.value)}
            />
            <Group>
              <Button type="submit" loading={busy} leftSection={<IconHistory size={18} />}>
                Zleć odtworzenie
              </Button>
            </Group>
          </Stack>
        </form>
      </Card>

      {error && <Alert color="red">{error}</Alert>}
      {items.length > 0 && (
        <Table.ScrollContainer minWidth={900}>
          <Table striped verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr style={{ whiteSpace: "nowrap" }}>
                <Table.Th>Nr</Table.Th>
                <Table.Th>Zakres</Table.Th>
                <Table.Th>Agenci</Table.Th>
                <Table.Th>Zlecił / powód</Table.Th>
                <Table.Th>Stan</Table.Th>
                <Table.Th>Odtworzono</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((x) => (
                <Table.Tr key={x.id}>
                  <Table.Td>{x.id}</Table.Td>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>{hourRange(x.from, x.to)}</Table.Td>
                  <Table.Td maw={200}>
                    <Text size="sm" lineClamp={2}>
                      {x.agents.length ? x.agents.join(", ") : "wszyscy"}
                    </Text>
                  </Table.Td>
                  <Table.Td maw={240}>
                    <Text size="sm">{x.requested_by}</Text>
                    <Text size="xs" c="dimmed" lineClamp={2} title={x.reason}>
                      {x.reason}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Tooltip label={x.error || formatDate(x.finished_at ?? x.started_at ?? x.requested_at)} multiline maw={400}>
                      <Badge color={replayStatusLabels[x.status].color} variant="light">
                        {replayStatusLabels[x.status].label}
                      </Badge>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>
                    <Text size="sm">
                      {formatNumber(x.batches)} paczek ({formatBytes(x.bytes)})
                    </Text>
                    {x.skipped > 0 && (
                      <Text size="xs" c="dimmed">
                        pominięte (inni agenci): {formatNumber(x.skipped)}
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    {(x.status === "done" || x.status === "running") && (
                      <Anchor component={Link} to={mimirLink(x)} size="sm">
                        pokaż w Mímirze
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
