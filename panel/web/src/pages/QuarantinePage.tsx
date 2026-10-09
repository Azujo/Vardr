import { useCallback, useEffect, useState } from "react";
import {
  Alert as MAlert,
  Anchor,
  Badge,
  Button,
  Code,
  Group,
  Modal,
  Progress,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconRefresh, IconRotateClockwise } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import {
  formatBytes,
  formatDate,
  quarantineApi,
  type QuarantineEntry,
  type QuarantineFilterParams,
  type QuarantineGroup,
  type QuarantineJob,
} from "../api";
import { useAuth } from "../auth";

const jobStatus: Record<QuarantineJob["status"], { label: string; color: string }> = {
  running: { label: "w toku", color: "blue" },
  done: { label: "zakończone", color: "green" },
  failed: { label: "błąd", color: "red" },
};

function supportedSource(s: string) {
  return s.startsWith("wineventlog:") || s.startsWith("syslog:");
}

function EntryRow({ e }: { e: QuarantineEntry }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Table.Tr style={{ cursor: "pointer", opacity: e.outcome?.recovered ? 0.5 : 1 }} onClick={() => setOpen((o) => !o)}>
        <Table.Td>
          <Text size="xs">{formatDate(e.ingested)}</Text>
        </Table.Td>
        <Table.Td>
          <Text size="xs" ff="monospace">
            {e.source}
          </Text>
          <Text size="xs" c="dimmed">
            {e.agent_id}
            {e.peer ? ` · ${e.peer}` : ""}
          </Text>
        </Table.Td>
        <Table.Td maw={520}>
          <Text size="xs" lineClamp={open ? undefined : 2} style={{ wordBreak: "break-word" }}>
            {e.reason}
          </Text>
        </Table.Td>
        <Table.Td>
          {e.outcome ? (
            e.outcome.recovered ? (
              <Badge color="green" size="sm">
                odzyskane (#{e.outcome.job_id})
              </Badge>
            ) : (
              <Tooltip label={e.outcome.reason} multiline w={360}>
                <Badge color="orange" size="sm">
                  nadal błędne (#{e.outcome.job_id})
                </Badge>
              </Tooltip>
            )
          ) : !e.supported ? (
            <Tooltip label="Wpis odrzucony przy zapisie do ClickHouse albo ze ścieżki odtwarzania – nie da się go przetworzyć ponownie">
              <Badge color="gray" size="sm" variant="outline">
                nie do przetworzenia
              </Badge>
            </Tooltip>
          ) : null}
        </Table.Td>
      </Table.Tr>
      {open && (
        <Table.Tr>
          <Table.Td colSpan={4}>
            <Text size="xs" c="dimmed">
              {e.event_id} · {formatBytes(e.raw_bytes)}
              {e.truncated ? " · treść przycięta przez agenta" : ""}
              {e.raw_bytes > e.raw.length ? " · podgląd: pierwsze 4000 znaków" : ""}
            </Text>
            <Code block fz="xs" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {e.raw}
            </Code>
          </Table.Td>
        </Table.Tr>
      )}
    </>
  );
}

export default function QuarantinePage() {
  const { user } = useAuth();
  const admin = user?.role === "admin";
  const [hours, setHours] = useState("168");
  const [source, setSource] = useState("");
  const [reason, setReason] = useState("");
  const [agent, setAgent] = useState("");
  const [applied, setApplied] = useState<QuarantineFilterParams>({ hours: 168 });
  const [groups, setGroups] = useState<QuarantineGroup[]>([]);
  const [entries, setEntries] = useState<QuarantineEntry[]>([]);
  const [jobs, setJobs] = useState<QuarantineJob[]>([]);
  const [total, setTotal] = useState(0);
  const [canReprocess, setCanReprocess] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [confirm, setConfirm] = useState<{ title: string; params: QuarantineFilterParams } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    quarantineApi
      .list(applied)
      .then((r) => {
        setGroups(r.groups);
        setEntries(r.entries);
        setJobs(r.jobs);
        setTotal(r.total);
        setCanReprocess(r.reprocess);
        setRunning(r.running);
        setError("");
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [applied]);
  useEffect(() => load(), [load]);
  // Postęp zlecenia w toku.
  useEffect(() => {
    if (!running && !jobs.some((j) => j.status === "running")) return;
    const t = setInterval(load, 2000);
    return () => clearInterval(t);
  }, [running, jobs, load]);

  const apply = () => setApplied({ hours: Number(hours), source: source.trim(), reason: reason.trim(), agent: agent.trim() });

  const start = async () => {
    if (!confirm) return;
    setBusy(true);
    try {
      const r = await quarantineApi.reprocess(confirm.params);
      notifications.show({
        color: "green",
        message: `Zlecenie #${r.job.id}: ${r.job.total} wpisów${r.limited ? " (pierwsze 10 000 – zleć ponownie dla reszty)" : ""}`,
      });
      setConfirm(null);
      setRunning(true);
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack>
      <div>
        <Title order={2}>Kwarantanna</Title>
        <Text c="dimmed" size="sm" maw={880}>
          Zdarzenia, których nie udało się znormalizować (np. treść niepasująca do dekodera, uszkodzony XML) albo zapisać – z oryginałem
          i powodem. Po poprawce dekodera (<Anchor component={Link} to="/decoders">Dekodery</Anchor>) albo programu można je przetworzyć
          ponownie: odzyskane zdarzenia trafiają do bazy i detekcji jak nowe (z polem <Code>siem.quarantined_at</Code>), a wpisy nadal
          błędne dostają aktualny powód. Archiwum NIS2 ma oryginały od początku – nic nie jest archiwizowane drugi raz.
        </Text>
      </div>
      {error && <MAlert color="red">{error}</MAlert>}
      {!canReprocess && !error && (
        <MAlert color="gray">Panel nie jest połączony z NATS – ponowne przetwarzanie niedostępne (podgląd działa).</MAlert>
      )}

      <Group align="flex-end" gap="xs">
        <Select
          label="Okres"
          w={160}
          allowDeselect={false}
          value={hours}
          onChange={(v) => setHours(v ?? "168")}
          data={[
            { value: "24", label: "ostatnie 24 h" },
            { value: "168", label: "ostatnie 7 dni" },
            { value: "720", label: "ostatnie 30 dni" },
            { value: "2160", label: "ostatnie 90 dni" },
          ]}
        />
        <TextInput label="Źródło (początek)" placeholder="syslog:" w={180} value={source} onChange={(e) => setSource(e.currentTarget.value)} />
        <TextInput label="Powód zawiera" w={220} value={reason} onChange={(e) => setReason(e.currentTarget.value)} />
        <TextInput label="Agent" w={200} value={agent} onChange={(e) => setAgent(e.currentTarget.value)} />
        <Button leftSection={<IconRefresh size={16} />} onClick={apply}>
          Pokaż
        </Button>
        {admin && canReprocess && total > 0 && (
          <Button
            variant="light"
            leftSection={<IconRotateClockwise size={16} />}
            disabled={running}
            onClick={() => setConfirm({ title: "wszystkie wpisy pasujące do filtra", params: applied })}
          >
            Przetwórz ponownie (filtr)
          </Button>
        )}
      </Group>

      {jobs.length > 0 && (
        <Stack gap={4}>
          <Text fw={600} size="sm">
            Zlecenia
          </Text>
          <Table verticalSpacing={4}>
            <Table.Tbody>
              {jobs.slice(0, 5).map((j) => (
                <Table.Tr key={j.id}>
                  <Table.Td w={60}>#{j.id}</Table.Td>
                  <Table.Td w={140}>
                    <Badge color={jobStatus[j.status].color}>{jobStatus[j.status].label}</Badge>
                  </Table.Td>
                  <Table.Td w={260}>
                    <Progress.Root size="lg">
                      <Progress.Section value={(100 * j.recovered) / Math.max(1, j.total)} color="green" />
                      <Progress.Section value={(100 * j.failed) / Math.max(1, j.total)} color="orange" />
                    </Progress.Root>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs">
                      odzyskane {j.recovered} · nadal błędne {j.failed} · razem {j.total} — {j.created_by}, {formatDate(j.created_at)}
                      {j.filter.source ? ` · źródło ${j.filter.source}` : ""}
                      {j.filter.reason ? ` · powód „${j.filter.reason}”` : ""}
                      {j.error ? ` · ${j.error}` : ""}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Stack>
      )}

      <Text fw={600} size="sm">
        Grupy ({total} wpisów)
      </Text>
      {groups.length === 0 ? (
        <Text size="sm" c="dimmed">
          Kwarantanna jest pusta w wybranym okresie.
        </Text>
      ) : (
        <Table.ScrollContainer minWidth={820}>
          <Table striped verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Źródło</Table.Th>
                <Table.Th>Powód (przykład)</Table.Th>
                <Table.Th>Wpisów</Table.Th>
                <Table.Th>Agentów</Table.Th>
                <Table.Th>Ostatni</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {groups.map((g, i) => (
                <Table.Tr key={i}>
                  <Table.Td>
                    <Text size="xs" ff="monospace">
                      {g.source}
                    </Text>
                  </Table.Td>
                  <Table.Td maw={460}>
                    <Text size="xs" lineClamp={2}>
                      {g.reason}
                    </Text>
                  </Table.Td>
                  <Table.Td>{g.count}</Table.Td>
                  <Table.Td>{g.agents}</Table.Td>
                  <Table.Td>
                    <Text size="xs">{formatDate(g.last)}</Text>
                  </Table.Td>
                  <Table.Td>
                    {admin && canReprocess && supportedSource(g.source) && (
                      <Button
                        size="compact-xs"
                        variant="subtle"
                        disabled={running}
                        onClick={() =>
                          setConfirm({
                            title: `grupa: ${g.source} – ${g.reason.slice(0, 80)}`,
                            // Grupa łączy powody różniące się liczbami – filtr: tekst do pierwszej cyfry.
                            params: { ...applied, source: g.source, reason: g.reason.split(/[0-9]/)[0].trim().slice(0, 200) },
                          })
                        }
                      >
                        przetwórz ponownie
                      </Button>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}

      {entries.length > 0 && (
        <>
          <Text fw={600} size="sm">
            Najnowsze wpisy ({entries.length}) – kliknij, aby zobaczyć oryginał
          </Text>
          <Table.ScrollContainer minWidth={820}>
            <Table verticalSpacing={4} highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th w={150}>Przyjęte</Table.Th>
                  <Table.Th w={220}>Źródło / agent</Table.Th>
                  <Table.Th>Powód</Table.Th>
                  <Table.Th w={190}>Ponowne przetworzenie</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {entries.map((e) => (
                  <EntryRow key={e.event_id + e.ingested} e={e} />
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </>
      )}

      <Modal opened={!!confirm} onClose={() => setConfirm(null)} title="Ponowne przetworzenie kwarantanny" centered>
        {confirm && (
          <Stack>
            <Text size="sm">
              Wpisy: {confirm.title}. Normalizator przetworzy je bieżącym kodem i dekoderami. Odzyskane zdarzenia trafią do bazy i do detekcji
              (mogą wywołać alerty), wpisy już odzyskane są pomijane. Najwyżej 10 000 wpisów w jednym zleceniu.
            </Text>
            <Group justify="flex-end">
              <Button loading={busy} onClick={() => void start()}>
                Przetwórz ponownie
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
