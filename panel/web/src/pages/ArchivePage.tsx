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
import { useTranslation } from "react-i18next";
import { locale } from "../i18n";
import { useAuth } from "../auth";
import ArchiveExports from "./ArchiveExports";
import ArchivePolicy from "./ArchivePolicy";
import ArchiveReplays from "./ArchiveReplays";
import { RecoveryTable, UnknownFiles, recoveryKindLabels } from "./ArchiveRecovery";

function hourLabel(iso?: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  const end = new Date(d.getTime() + 3600_000);
  const hm: Intl.DateTimeFormatOptions = { hour: "2-digit", minute: "2-digit" };
  return `${d.toLocaleDateString(locale())} ${d.toLocaleTimeString(locale(), hm)}–${end.toLocaleTimeString(locale(), hm)}`;
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
  const { t } = useTranslation("archive");
  return (
    <CopyButton value={value}>
      {({ copied, copy }) => (
        <Tooltip label={copied ? t("copied") : value} maw={600} multiline>
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
  const { t } = useTranslation("archive");
  return (
    <Table.ScrollContainer minWidth={820}>
      <Table striped verticalSpacing="xs">
        <Table.Thead>
          <Table.Tr style={{ whiteSpace: "nowrap" }}>
            <Table.Th>{t("manifest.hour")}</Table.Th>
            <Table.Th>{t("manifest.no")}</Table.Th>
            <Table.Th>{t("manifest.segments")}</Table.Th>
            <Table.Th>{t("manifest.batches")}</Table.Th>
            <Table.Th>{t("manifest.size")}</Table.Th>
            <Table.Th>{t("manifest.sha")}</Table.Th>
            <Table.Th>{t("manifest.chain")}</Table.Th>
            <Table.Th>{t("manifest.data")}</Table.Th>
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
                      linked ? t("manifest.linked", { hash: m.prev_sha256.slice(0, 16) }) : t("manifest.broken")
                    }
                  >
                    {linked ? <IconLink size={16} color="var(--mantine-color-green-6)" /> : <IconLinkOff size={16} color="var(--mantine-color-red-6)" />}
                  </Tooltip>
                </Table.Td>
                <Table.Td>
                  {m.expired_at ? (
                    <Tooltip label={t("manifest.expiredTip", { date: formatDate(m.expired_at) })}>
                      <Badge size="sm" color="gray" variant="light">
                        {t("manifest.expired")}
                      </Badge>
                    </Tooltip>
                  ) : m.verified_at ? (
                    <Tooltip label={t("manifest.verifiedTip", { date: formatDate(m.verified_at) })}>
                      <Badge size="sm" color="green" variant="light">
                        {t("manifest.verified")}
                      </Badge>
                    </Tooltip>
                  ) : (
                    <Tooltip label={t("manifest.storedTip")}>
                      <Badge size="sm" color="blue" variant="light">
                        {t("manifest.stored")}
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
  const { t } = useTranslation("archive");
  return (
    <Table.ScrollContainer minWidth={820}>
      <Table striped verticalSpacing="xs">
        <Table.Thead>
          <Table.Tr style={{ whiteSpace: "nowrap" }}>
            <Table.Th>{t("verif.finished")}</Table.Th>
            <Table.Th>{t("verif.result")}</Table.Th>
            <Table.Th>{t("verif.manifests")}</Table.Th>
            <Table.Th>{t("manifest.segments")}</Table.Th>
            <Table.Th>{t("verif.full")}</Table.Th>
            <Table.Th>{t("manifest.batches")}</Table.Th>
            <Table.Th>{t("verif.read")}</Table.Th>
            <Table.Th>{t("verif.time")}</Table.Th>
            <Table.Th>{t("verif.problems")}</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {items.map((v) => (
            <Table.Tr key={v.id}>
              <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(v.finished_at)}</Table.Td>
              <Table.Td>
                <Badge color={v.ok ? "green" : "red"} variant="light">
                  {v.ok ? t("verif.ok") : t("verif.bad")}
                </Badge>
              </Table.Td>
              <Table.Td>{v.manifests}</Table.Td>
              <Table.Td>{v.segments}</Table.Td>
              <Table.Td>
                <Tooltip label={t("verif.fullTip")}>
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
                      {r.processed_at ? t("verif.resolved") : t("verif.requested")}: #{r.id} {recoveryKindLabels[r.kind]}
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
  const { t } = useTranslation("archive");
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
      await archiveApi.verify();
      notifications.show({ color: "green", message: t("verifyRequested") });
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
          <Title order={2}>{t("title")}</Title>
          <Text c="dimmed" size="sm" maw={820}>
            {t("intro")}
          </Text>
        </div>
        {can("archive", "write") && data && data.compliance !== "not_configured" && (
          <Button
            leftSection={<IconShieldCheck size={18} />}
            onClick={() => void verify()}
            loading={busy}
            disabled={!!st?.verify_requested_at}
          >
            {st?.verify_requested_at ? t("verifyPending") : t("verifyNow")}
          </Button>
        )}
      </Group>
      {error && <Alert color="red">{error}</Alert>}

      {c && (
        <Alert
          color={c.color}
          variant="light"
          title={t("state", { label: c.label })}
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
            {t("unknownFiles", { count: lv.unknown.length })}
          </Alert>
        )
      )}

      {st && sum && (
        <SimpleGrid cols={{ base: 2, md: 3, xl: 6 }}>
          <Stat
            label={t("stat.archiver")}
            value={
              <Badge size="lg" color={data?.archiver_running ? "green" : "red"} variant="light">
                {data?.archiver_running ? t("stat.running") : t("stat.noSignal")}
              </Badge>
            }
            sub={t("stat.archiverSub", { version: st.version, ago: ago(st.heartbeat_at) })}
          />
          <Stat label={t("stat.data")} value={formatBytes(sum.bytes + sum.open_bytes)} sub={t("stat.batches", { n: formatNumber(sum.batches + sum.open_batches) })} />
          <Stat
            label={t("stat.range")}
            value={`${sum.manifests} h`}
            sub={sum.oldest_hour ? t("stat.since", { date: formatDate(sum.oldest_hour) }) : t("stat.firstManifest")}
          />
          <Stat
            label={t("stat.retention")}
            value={t("days", { n: st.retention_days })}
            sub={data?.policy && !data.policy.enabled ? t("stat.disabled") : t("stat.chain", { n: sum.manifests_total })}
          />
          <Stat
            label={t("stat.disk")}
            value={
              st.disk_total_bytes ? (
                <Text fz={22} fw={700} c={st.paused ? "red" : st.disk_free_bytes < 0.15 * st.disk_total_bytes ? "orange" : undefined}>
                  {t("stat.free", { size: formatBytes(st.disk_free_bytes) })}
                </Text>
              ) : (
                "—"
              )
            }
            sub={
              st.disk_total_bytes
                ? t("stat.of", { size: formatBytes(st.disk_total_bytes), pct: Math.round((100 * st.disk_free_bytes) / st.disk_total_bytes) })
                : t("stat.noMeasure")
            }
          />
          <Stat
            label={t("stat.lastVerify")}
            value={
              lv ? (
                <Badge size="lg" color={lv.ok ? "green" : "red"} variant="light">
                  {lv.ok ? t("verif.ok") : t("verif.bad")}
                </Badge>
              ) : (
                "—"
              )
            }
            sub={
              lv
                ? `${ago(lv.finished_at)}, ${t("stat.every", { h: Math.round(st.verify_every_s / 3600) })}; ` +
                  (lv.oldest_full_check
                    ? t("stat.fullSince", { date: formatDate(lv.oldest_full_check) })
                    : t("stat.waiting", { h: lv.unverified }))
                : t("stat.every", { h: Math.round(st.verify_every_s / 3600) })
            }
          />
        </SimpleGrid>
      )}

      {sum && sum.open_segments > 0 && (
        <Text size="sm" c="dimmed">
          {t("currentHour", {
            segments: sum.open_segments,
            batches: formatNumber(sum.open_batches),
            size: formatBytes(sum.open_bytes),
            ago: ago(sum.last_segment_at),
          })}
        </Text>
      )}

      {data && data.compliance !== "not_configured" && (
        <Tabs defaultValue="manifests">
          <Tabs.List>
            <Tabs.Tab value="manifests">{t("tab.manifests", { n: data.manifests?.length ?? 0 })}</Tabs.Tab>
            <Tabs.Tab value="verifications">{t("tab.verifications", { n: data.verifications?.length ?? 0 })}</Tabs.Tab>
            <Tabs.Tab value="recoveries">{t("tab.recoveries", { n: recoveries.length })}</Tabs.Tab>
            <Tabs.Tab value="policy">{t("tab.policy")}</Tabs.Tab>
            {can("archive", "export") && <Tabs.Tab value="exports">{t("tab.exports")}</Tabs.Tab>}
            {can("archive", "write") && <Tabs.Tab value="replays">{t("tab.replays")}</Tabs.Tab>}
          </Tabs.List>
          <Tabs.Panel value="manifests" pt="sm">
            {data.manifests?.length ? (
              <ManifestTable manifests={data.manifests} />
            ) : (
              <Text size="sm" c="dimmed">
                {t("noManifests")}
              </Text>
            )}
          </Tabs.Panel>
          <Tabs.Panel value="verifications" pt="sm">
            {data.verifications?.length ? (
              <VerificationTable items={data.verifications} recoveries={recoveries} />
            ) : (
              <Text size="sm" c="dimmed">
                {t("noVerifications")}
              </Text>
            )}
          </Tabs.Panel>
          <Tabs.Panel value="recoveries" pt="sm">
            <Text size="sm" c="dimmed" mb="xs" maw={900}>
              {t("recoveriesIntro")}
            </Text>
            {recoveries.length ? (
              <RecoveryTable items={recoveries} />
            ) : (
              <Text size="sm" c="dimmed">
                {t("noRecoveries")}
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
        <Alert color="gray" title={t("howToEnable")}>
          {t("howToEnableText")}
        </Alert>
      )}
    </Stack>
  );
}
