// SPDX-License-Identifier: AGPL-3.0-or-later

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
import { IconRefresh, IconRotateClockwise, IconWand } from "@tabler/icons-react";
import { Link, useNavigate } from "react-router-dom";
import DecoderWizard from "./DecoderWizard";
import {
  formatBytes,
  formatDate,
  quarantineApi,
  type QuarantineEntry,
  type QuarantineFilterParams,
  type QuarantineGroup,
  type QuarantineJob,
} from "../api";
import { useTranslation } from "react-i18next";
import { useAuth } from "../auth";

const jobColors: Record<QuarantineJob["status"], string> = { running: "blue", done: "green", failed: "red" };

function supportedSource(s: string) {
  return s.startsWith("wineventlog:") || s.startsWith("syslog:") || s.startsWith("entra:");
}

function EntryRow({ e }: { e: QuarantineEntry }) {
  const { t } = useTranslation("quarantine");
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
                {t("entry.recovered", { id: e.outcome.job_id })}
              </Badge>
            ) : (
              <Tooltip label={e.outcome.reason} multiline w={360}>
                <Badge color="orange" size="sm">
                  {t("entry.stillFailed", { id: e.outcome.job_id })}
                </Badge>
              </Tooltip>
            )
          ) : !e.supported ? (
            <Tooltip label={t("entry.unsupportedTip")}>
              <Badge color="gray" size="sm" variant="outline">
                {t("entry.unsupported")}
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
              {e.truncated ? ` · ${t("entry.truncated")}` : ""}
              {e.raw_bytes > e.raw.length ? ` · ${t("entry.preview")}` : ""}
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
  const { t } = useTranslation("quarantine");
  const { can } = useAuth();
  const admin = can("quarantine", "write");
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
  const [wizard, setWizard] = useState<{ samples: string[]; peer?: string } | null>(null);
  const navigate = useNavigate();

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
        message: t("jobStarted", { id: r.job.id, count: r.job.total }) + (r.limited ? t("jobLimited") : ""),
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
        <Title order={2}>{t("title")}</Title>
        <Text c="dimmed" size="sm" maw={880}>
          {t("intro.0")}
          <Anchor component={Link} to="/decoders">
            {t("intro.1")}
          </Anchor>
          {t("intro.2")}
        </Text>
      </div>
      {error && <MAlert color="red">{error}</MAlert>}
      {!canReprocess && !error && (
        <MAlert color="gray">{t("noNats")}</MAlert>
      )}

      <Group align="flex-end" gap="xs">
        <Select
          label={t("filter.period")}
          w={160}
          allowDeselect={false}
          value={hours}
          onChange={(v) => setHours(v ?? "168")}
          data={[
            { value: "24", label: t("filter.h24") },
            { value: "168", label: t("filter.d7") },
            { value: "720", label: t("filter.d30") },
            { value: "2160", label: t("filter.d90") },
          ]}
        />
        <TextInput label={t("filter.source")} placeholder="syslog:" w={180} value={source} onChange={(e) => setSource(e.currentTarget.value)} />
        <TextInput label={t("filter.reason")} w={220} value={reason} onChange={(e) => setReason(e.currentTarget.value)} />
        <TextInput label={t("filter.agent")} w={200} value={agent} onChange={(e) => setAgent(e.currentTarget.value)} />
        <Button leftSection={<IconRefresh size={16} />} onClick={apply}>
          {t("filter.show")}
        </Button>
        {admin && canReprocess && total > 0 && (
          <Button
            variant="light"
            leftSection={<IconRotateClockwise size={16} />}
            disabled={running}
            onClick={() => setConfirm({ title: t("confirm.allFiltered"), params: applied })}
          >
            {t("reprocessFilter")}
          </Button>
        )}
      </Group>

      {jobs.length > 0 && (
        <Stack gap={4}>
          <Text fw={600} size="sm">
            {t("jobs")}
          </Text>
          <Table verticalSpacing={4}>
            <Table.Tbody>
              {jobs.slice(0, 5).map((j) => (
                <Table.Tr key={j.id}>
                  <Table.Td w={60}>#{j.id}</Table.Td>
                  <Table.Td w={140}>
                    <Badge color={jobColors[j.status]}>{t(`jobStatus.${j.status}`)}</Badge>
                  </Table.Td>
                  <Table.Td w={260}>
                    <Progress.Root size="lg">
                      <Progress.Section value={(100 * j.recovered) / Math.max(1, j.total)} color="green" />
                      <Progress.Section value={(100 * j.failed) / Math.max(1, j.total)} color="orange" />
                    </Progress.Root>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs">
                      {t("job", { recovered: j.recovered, failed: j.failed, total: j.total, by: j.created_by, date: formatDate(j.created_at) })}
                      {j.filter.source ? ` · ${t("jobSource", { source: j.filter.source })}` : ""}
                      {j.filter.reason ? ` · ${t("jobReason", { reason: j.filter.reason })}` : ""}
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
        {t("groups", { count: total })}
      </Text>
      {groups.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("empty")}
        </Text>
      ) : (
        <Table.ScrollContainer minWidth={820}>
          <Table striped verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("col.source")}</Table.Th>
                <Table.Th>{t("col.reasonSample")}</Table.Th>
                <Table.Th>{t("col.count")}</Table.Th>
                <Table.Th>{t("col.agents")}</Table.Th>
                <Table.Th>{t("col.last")}</Table.Th>
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
                    {g.source.startsWith("syslog:") && can("decoders", "test") && (
                      <Button
                        size="compact-xs"
                        variant="subtle"
                        leftSection={<IconWand size={12} />}
                        onClick={() => {
                          const prefix = g.reason.split(/[0-9]/)[0].trim();
                          const mine = entries.filter((e) => e.source === g.source && e.reason.startsWith(prefix) && !e.truncated);
                          const peers = new Set(mine.map((e) => e.peer).filter(Boolean));
                          setWizard({ samples: mine.map((e) => e.raw), peer: peers.size === 1 ? [...peers][0] : undefined });
                        }}
                      >
                        {t("decoderWizard")}
                      </Button>
                    )}
                    {admin && canReprocess && supportedSource(g.source) && (
                      <Button
                        size="compact-xs"
                        variant="subtle"
                        disabled={running}
                        onClick={() =>
                          setConfirm({
                            title: t("confirm.group", { source: g.source, reason: g.reason.slice(0, 80) }),
                            // Grupa łączy powody różniące się liczbami – filtr: tekst do pierwszej cyfry.
                            params: { ...applied, source: g.source, reason: g.reason.split(/[0-9]/)[0].trim().slice(0, 200) },
                          })
                        }
                      >
                        {t("reprocessShort")}
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
            {t("entries", { count: entries.length })}
          </Text>
          <Table.ScrollContainer minWidth={820}>
            <Table verticalSpacing={4} highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th w={150}>{t("col.ingested")}</Table.Th>
                  <Table.Th w={220}>{t("col.sourceAgent")}</Table.Th>
                  <Table.Th>{t("col.reason")}</Table.Th>
                  <Table.Th w={190}>{t("col.reprocess")}</Table.Th>
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

      <Modal opened={!!confirm} onClose={() => setConfirm(null)} title={t("confirm.title")} centered>
        {confirm && (
          <Stack>
            <Text size="sm">
              {t("confirm.text", { what: confirm.title })}
            </Text>
            <Group justify="flex-end">
              <Button loading={busy} onClick={() => void start()}>
                {t("confirm.run")}
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
      <Modal opened={!!wizard} onClose={() => setWizard(null)} title={t("wizardTitle")} size="95%">
        {wizard && (
          <DecoderWizard
            initialSamples={wizard.samples}
            initialPeer={wizard.peer}
            admin={admin}
            samplesAvailable
            onEdit={(yaml) => navigate("/decoders", { state: { draft: yaml } })}
            onSaved={() => {
              setWizard(null);
              notifications.show({ color: "green", message: t("decoderSaved") });
            }}
          />
        )}
      </Modal>
    </Stack>
  );
}
