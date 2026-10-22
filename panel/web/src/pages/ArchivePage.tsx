// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  CopyButton,
  Group,
  List,
  SimpleGrid,
  Stack,
  Table,
  Tabs,
  Text,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCheck, IconLink, IconLinkOff, IconShieldCheck } from "@tabler/icons-react";
import {
  ago,
  archiveApi,
  complianceLabels,
  formatBytes,
  formatDate,
  formatNumber,
  type ArchiveManifest,
  type ArchiveOverview,
  type ArchiveRecovery,
  type ArchiveVerification,
} from "../api";
import { useAuth } from "../auth";
import ArchiveExports from "./ArchiveExports";
import ArchivePolicy from "./ArchivePolicy";
import ArchiveReplays from "./ArchiveReplays";
import { RecoveryTable, UnknownFiles, recoveryKindLabels } from "./ArchiveRecovery";

function hourLabel(iso?: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  const end = new Date(d.getTime() + 3600_000);
  return `${d.toLocaleDateString("pl-PL")} ${d.toLocaleTimeString("pl-PL", { hour: "2-digit", minute: "2-digit" })}–${end.toLocaleTimeString("pl-PL", { hour: "2-digit", minute: "2-digit" })}`;
}

function duration(v: ArchiveVerification) {
  const ms = new Date(v.finished_at).getTime() - new Date(v.started_at).getTime();
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

function Stat({ label, value, sub }: { label: string; value: React.ReactNode; sub?: React.ReactNode }) {
  return (
    <Card withBorder padding="md">
      <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
        {label}
      </Text>
      <Text fz={22} fw={700}>
        {value}
      </Text>
      {sub && (
        <Text size="xs" c="dimmed">
          {sub}
        </Text>
      )}
    </Card>
  );
}

function Hash({ value }: { value: string }) {
  return (
    <CopyButton value={value}>
      {({ copied, copy }) => (
        <Tooltip label={copied ? "skopiowano" : value} maw={600} multiline>
          <Text size="xs" ff="monospace" c="dimmed" style={{ cursor: "pointer" }} onClick={copy}>
            {value.slice(0, 16)}…
          </Text>
        </Tooltip>
      )}
    </CopyButton>
  );
}

// Manifesty są od najnowszego: poprzednikiem wiersza i jest wiersz i+1.
function ManifestTable({ manifests }: { manifests: ArchiveManifest[] }) {
  return (
    <Table.ScrollContainer minWidth={820}>
      <Table striped verticalSpacing="xs">
        <Table.Thead>
          <Table.Tr style={{ whiteSpace: "nowrap" }}>
            <Table.Th>Godzina</Table.Th>
            <Table.Th>Nr</Table.Th>
            <Table.Th>Segmenty</Table.Th>
            <Table.Th>Paczki</Table.Th>
            <Table.Th>Rozmiar</Table.Th>
            <Table.Th>SHA-256 manifestu</Table.Th>
            <Table.Th>Łańcuch</Table.Th>
            <Table.Th>Dane</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {manifests.map((m, i) => {
            const prev = manifests[i + 1];
            const linked = prev ? prev.sha256 === m.prev_sha256 : true;
            return (
              <Table.Tr key={m.seq}>
                <Table.Td style={{ whiteSpace: "nowrap" }}>{hourLabel(m.hour)}</Table.Td>
                <Table.Td>{m.seq}</Table.Td>
                <Table.Td>{m.segments}</Table.Td>
                <Table.Td>{formatNumber(m.records)}</Table.Td>
                <Table.Td>{formatBytes(m.bytes)}</Table.Td>
                <Table.Td>
                  <Hash value={m.sha256} />
                </Table.Td>
                <Table.Td>
                  <Tooltip
                    label={
                      linked
                        ? `Hash poprzednika: ${m.prev_sha256.slice(0, 16)}… – zgodny z poprzednim manifestem`
                        : "Hash poprzednika nie zgadza się z poprzednim wierszem"
                    }
                  >
                    {linked ? <IconLink size={16} color="var(--mantine-color-green-6)" /> : <IconLinkOff size={16} color="var(--mantine-color-red-6)" />}
                  </Tooltip>
                </Table.Td>
                <Table.Td>
                  {m.expired_at ? (
                    <Tooltip label={`Dane usunięte po retencji ${formatDate(m.expired_at)}; wpis zostaje w łańcuchu`}>
                      <Badge size="sm" color="gray" variant="light">
                        wygasłe
                      </Badge>
                    </Tooltip>
                  ) : m.verified_at ? (
                    <Tooltip label={`Treść sprawdzona w całości (SHA-256 każdej paczki) ${formatDate(m.verified_at)}`}>
                      <Badge size="sm" color="green" variant="light">
                        sprawdzone
                      </Badge>
                    </Tooltip>
                  ) : (
                    <Tooltip label="W archiwum; pełne sprawdzenie treści w kolejnych przebiegach weryfikacji (obecność i rozmiar plików są sprawdzane zawsze)">
                      <Badge size="sm" color="blue" variant="light">
                        w archiwum
                      </Badge>
                    </Tooltip>
                  )}
                </Table.Td>
              </Table.Tr>
            );
          })}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}

function VerificationTable({ items, recoveries }: { items: ArchiveVerification[]; recoveries: ArchiveRecovery[] }) {
  return (
    <Table.ScrollContainer minWidth={820}>
      <Table striped verticalSpacing="xs">
        <Table.Thead>
          <Table.Tr style={{ whiteSpace: "nowrap" }}>
            <Table.Th>Zakończona</Table.Th>
            <Table.Th>Wynik</Table.Th>
            <Table.Th>Manifesty</Table.Th>
            <Table.Th>Segmenty</Table.Th>
            <Table.Th>W całości</Table.Th>
            <Table.Th>Paczki</Table.Th>
            <Table.Th>Odczytano</Table.Th>
            <Table.Th>Czas</Table.Th>
            <Table.Th>Problemy</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {items.map((v) => (
            <Table.Tr key={v.id}>
              <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(v.finished_at)}</Table.Td>
              <Table.Td>
                <Badge color={v.ok ? "green" : "red"} variant="light">
                  {v.ok ? "zgodne" : "niezgodności"}
                </Badge>
              </Table.Td>
              <Table.Td>{v.manifests}</Table.Td>
              <Table.Td>{v.segments}</Table.Td>
              <Table.Td>
                <Tooltip label="Manifesty, których treść odczytano i sprawdzono w całości w tym przebiegu">
                  <Text size="sm">{v.full_manifests}</Text>
                </Tooltip>
              </Table.Td>
              <Table.Td>{formatNumber(v.records)}</Table.Td>
              <Table.Td>{formatBytes(v.bytes)}</Table.Td>
              <Table.Td>{duration(v)}</Table.Td>
              <Table.Td maw={360}>
                {v.problems.length === 0 ? (
                  <Text size="sm" c="dimmed">
                    —
                  </Text>
                ) : (
                  <Tooltip label={v.problems.join("\n")} multiline maw={600} style={{ whiteSpace: "pre-line" }}>
                    <Text size="sm" c="red" lineClamp={2}>
                      {v.problems.length}: {v.problems[0]}
                    </Text>
                  </Tooltip>
                )}
                {recoveries
                  .filter((r) => r.verification_id === v.id)
                  .map((r) => (
                    <Badge key={r.id} size="xs" variant="light" color={r.processed_at && r.ok !== false ? "teal" : "gray"} mt={2}>
                      {r.processed_at ? "rozstrzygnięte" : "zlecone"}: #{r.id} {recoveryKindLabels[r.kind]}
                    </Badge>
                  ))}
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}

export default function ArchivePage() {
  const { can } = useAuth();
  const [data, setData] = useState<ArchiveOverview | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    archiveApi
      .overview()
      .then((d) => {
        setData(d);
        setError("");
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);
  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [load]);

  const verify = async () => {
    setBusy(true);
    try {
      const r = await archiveApi.verify();
      notifications.show({ color: "green", message: r.message });
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  const c = data ? complianceLabels[data.compliance] : null;
  const st = data?.archiver;
  const sum = data?.summary;
  const lv = data?.last_verification;
  const recoveries = data?.recoveries ?? [];
  const pendingDecision = recoveries.find((r) => !r.processed_at && r.kind !== "restore");

  return (
    <Stack>
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>Urd – archiwum NIS2</Title>
          <Text c="dimmed" size="sm" maw={820}>
            Oryginalne paczki logów zapisane przed normalizacją. Każda godzina ma manifest z sumami SHA-256 segmentów,
            powiązany z poprzednim hashem (łańcuch). Weryfikacja wykrywa zmianę, usunięcie lub dodanie danych.
          </Text>
        </div>
        {can("archive", "write") && data && data.compliance !== "not_configured" && (
          <Button
            leftSection={<IconShieldCheck size={18} />}
            onClick={() => void verify()}
            loading={busy}
            disabled={!!st?.verify_requested_at}
          >
            {st?.verify_requested_at ? "Weryfikacja zlecona…" : "Zweryfikuj teraz"}
          </Button>
        )}
      </Group>
      {error && <Alert color="red">{error}</Alert>}

      {c && (
        <Alert
          color={c.color}
          variant="light"
          title={`Stan archiwum: ${c.label}`}
          icon={data?.compliance === "ok" ? <IconCheck /> : undefined}
        >
          <Text size="sm">{c.hint}</Text>
          {st?.paused && (
            <Text size="sm" fw={600} mt={4}>
              {st.paused}
            </Text>
          )}
          {data?.compliance === "problems" && lv && (
            <List size="sm" mt="xs" spacing={2}>
              {lv.problems.slice(0, 20).map((p, i) => (
                <List.Item key={i}>{p}</List.Item>
              ))}
            </List>
          )}
        </Alert>
      )}

      {lv && !lv.ok && !!lv.unknown?.length && (
        can("archive", "write") ? (
          <UnknownFiles verification={lv} pending={pendingDecision} onDone={load} />
        ) : (
          <Alert color="orange" variant="light">
            Ostatnia weryfikacja znalazła {lv.unknown.length} plików nieznanych spisowi – o ich przyjęciu albo kwarantannie decyduje
            administrator.
          </Alert>
        )
      )}

      {st && sum && (
        <SimpleGrid cols={{ base: 2, md: 3, xl: 6 }}>
          <Stat
            label="Archiwizator"
            value={
              <Badge size="lg" color={data?.archiver_running ? "green" : "red"} variant="light">
                {data?.archiver_running ? "działa" : "brak sygnału"}
              </Badge>
            }
            sub={`wersja ${st.version}, sygnał ${ago(st.heartbeat_at)}`}
          />
          <Stat label="Dane w archiwum" value={formatBytes(sum.bytes + sum.open_bytes)} sub={`${formatNumber(sum.batches + sum.open_batches)} paczek`} />
          <Stat
            label="Zakres"
            value={`${sum.manifests} h`}
            sub={sum.oldest_hour ? `od ${formatDate(sum.oldest_hour)}` : "pierwszy manifest po pełnej godzinie"}
          />
          <Stat
            label="Retencja"
            value={`${st.retention_days} dni`}
            sub={
              data?.policy && !data.policy.enabled
                ? "archiwizacja nowych paczek WYŁĄCZONA"
                : `łańcuch: ${sum.manifests_total} manifestów od początku`
            }
          />
          <Stat
            label="Dysk archiwum"
            value={
              st.disk_total_bytes ? (
                <Text fz={22} fw={700} c={st.paused ? "red" : st.disk_free_bytes < 0.15 * st.disk_total_bytes ? "orange" : undefined}>
                  {formatBytes(st.disk_free_bytes)} wolne
                </Text>
              ) : (
                "—"
              )
            }
            sub={
              st.disk_total_bytes
                ? `z ${formatBytes(st.disk_total_bytes)} (${Math.round((100 * st.disk_free_bytes) / st.disk_total_bytes)}%)`
                : "brak pomiaru"
            }
          />
          <Stat
            label="Ostatnia weryfikacja"
            value={
              lv ? (
                <Badge size="lg" color={lv.ok ? "green" : "red"} variant="light">
                  {lv.ok ? "zgodne" : "niezgodności"}
                </Badge>
              ) : (
                "—"
              )
            }
            sub={
              lv
                ? `${ago(lv.finished_at)}, co ${Math.round(st.verify_every_s / 3600)} h; ` +
                  (lv.oldest_full_check
                    ? `całość sprawdzona od ${formatDate(lv.oldest_full_check)}`
                    : `${lv.unverified} h czeka na pełne sprawdzenie`)
                : `co ${Math.round(st.verify_every_s / 3600)} h`
            }
          />
        </SimpleGrid>
      )}

      {sum && sum.open_segments > 0 && (
        <Text size="sm" c="dimmed">
          Bieżąca godzina: {sum.open_segments} segmentów, {formatNumber(sum.open_batches)} paczek ({formatBytes(sum.open_bytes)}),
          ostatni zapis {ago(sum.last_segment_at)} – manifest powstanie po pełnej godzinie.
        </Text>
      )}

      {data && data.compliance !== "not_configured" && (
        <Tabs defaultValue="manifests">
          <Tabs.List>
            <Tabs.Tab value="manifests">Manifesty ({data.manifests?.length ?? 0})</Tabs.Tab>
            <Tabs.Tab value="verifications">Weryfikacje ({data.verifications?.length ?? 0})</Tabs.Tab>
            <Tabs.Tab value="recoveries">Obsługa niezgodności ({recoveries.length})</Tabs.Tab>
            <Tabs.Tab value="policy">Polityka</Tabs.Tab>
            {can("archive", "export") && <Tabs.Tab value="exports">Eksport dla audytora</Tabs.Tab>}
            {can("archive", "write") && <Tabs.Tab value="replays">Odtworzenie</Tabs.Tab>}
          </Tabs.List>
          <Tabs.Panel value="manifests" pt="sm">
            {data.manifests?.length ? (
              <ManifestTable manifests={data.manifests} />
            ) : (
              <Text size="sm" c="dimmed">
                Jeszcze nie ma manifestów – pierwszy powstanie po pełnej godzinie pracy archiwizatora.
              </Text>
            )}
          </Tabs.Panel>
          <Tabs.Panel value="verifications" pt="sm">
            {data.verifications?.length ? (
              <VerificationTable items={data.verifications} recoveries={recoveries} />
            ) : (
              <Text size="sm" c="dimmed">
                Jeszcze nie było weryfikacji.
              </Text>
            )}
          </Tabs.Panel>
          <Tabs.Panel value="recoveries" pt="sm">
            <Text size="sm" c="dimmed" mb="xs" maw={900}>
              Uzgodnienia spisu archiwum z plikami na dysku: automatyczne po przywróceniu kopii bazy (pliki zapisane między zrzutem a
              przywróceniem, po sprawdzeniu sum i łańcucha) oraz decyzje administratora. Każda operacja jest też zapisana jako plik
              w katalogu archiwum <code>recoveries/</code> – przetrwa kolejne przywrócenie bazy.
            </Text>
            {recoveries.length ? (
              <RecoveryTable items={recoveries} />
            ) : (
              <Text size="sm" c="dimmed">
                Nie było jeszcze żadnej obsługi niezgodności.
              </Text>
            )}
          </Tabs.Panel>
          <Tabs.Panel value="policy" pt="sm">
            <ArchivePolicy admin={can("archive", "write")} onChanged={load} />
          </Tabs.Panel>
          {can("archive", "export") && (
            <Tabs.Panel value="exports" pt="sm">
              <ArchiveExports />
            </Tabs.Panel>
          )}
          {can("archive", "write") && (
            <Tabs.Panel value="replays" pt="sm">
              <ArchiveReplays />
            </Tabs.Panel>
          )}
        </Tabs>
      )}

      {data?.compliance === "not_configured" && (
        <Alert color="gray" title="Jak włączyć archiwum">
          Uruchom usługę <code>archiver</code> w stosie laboratoryjnym (katalog <code>archive</code> należący do użytkownika
          1000) – szczegóły w README, sekcja „Archiwum NIS2 – Urd”.
        </Alert>
      )}
    </Stack>
  );
}
