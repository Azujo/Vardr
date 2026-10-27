// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  Code,
  Group,
  List,
  Radio,
  ScrollArea,
  Stack,
  Table,
  Text,
  Textarea,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useTranslation } from "react-i18next";
import i18n from "../i18n";
import { ApiError, archiveApi, formatDate, type ArchiveRecovery, type ArchiveVerification } from "../api";
import { ReauthPassword } from "../sso";

// Rodzaje obsługi tłumaczone przy odczycie (archive: recovery.kind.*).
export const recoveryKindLabels = Object.defineProperties({} as Record<ArchiveRecovery["kind"], string>, {
  restore: { enumerable: true, get: () => i18n.t("archive:recovery.kind.restore") },
  adopt: { enumerable: true, get: () => i18n.t("archive:recovery.kind.adopt") },
  quarantine: { enumerable: true, get: () => i18n.t("archive:recovery.kind.quarantine") },
});

export function recoverySummary(r: ArchiveRecovery): string {
  const t = (k: string, o?: Record<string, unknown>) => i18n.t(`archive:recovery.summary.${k}`, o);
  if (!r.processed_at) return t("waiting");
  if (r.ok === false) return t("failed", { error: r.error });
  const res = r.result;
  if (!res) return t("done");
  const parts: string[] = [];
  if (res.manifests.length) parts.push(t("manifests", { n: res.manifests.length }));
  if (res.segments.length) parts.push(t("segments", { n: res.segments.length }));
  if (res.quarantined.length) parts.push(t("quarantined", { n: res.quarantined.length }));
  if (res.rejected.length) parts.push(t("rejected", { n: res.rejected.length }));
  return parts.join(", ") || t("nothing");
}

// Decyzja administratora o plikach nieznanych spisowi (z ostatniej weryfikacji).
export function UnknownFiles({
  verification,
  pending,
  onDone,
}: {
  verification: ArchiveVerification;
  pending?: ArchiveRecovery;
  onDone: () => void;
}) {
  const { t } = useTranslation("archive");
  const files = verification.unknown ?? [];
  const [sel, setSel] = useState<string[]>(files);
  const [action, setAction] = useState<"adopt" | "quarantine">("adopt");
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => setSel(verification.unknown ?? []), [verification.id, verification.unknown]);

  const send = async () => {
    setBusy(true);
    try {
      await archiveApi.recovery(action, sel, reason.trim(), password);
      notifications.show({ color: "green", message: t("recovery.requested", { kind: recoveryKindLabels[action] }) });
      setReason("");
      setPassword("");
      onDone();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof ApiError || e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  if (pending) {
    return (
      <Alert color="blue" title={t("recovery.pendingTitle", { id: pending.id })}>
        <Text size="sm">
          {t("recovery.pendingText", { kind: recoveryKindLabels[pending.kind], n: pending.paths.length, by: pending.requested_by })}
        </Text>
      </Alert>
    );
  }
  return (
    <Card withBorder>
      <Stack gap="xs">
        <Text fw={600}>{t("recovery.unknownTitle", { n: files.length })}</Text>
        <Text size="sm" c="dimmed">
          {t("recovery.unknownText")}
        </Text>
        <ScrollArea.Autosize mah={220}>
          <Table fz="xs" verticalSpacing={2}>
            <Table.Tbody>
              {files.map((f) => (
                <Table.Tr key={f}>
                  <Table.Td w={30}>
                    <Checkbox
                      size="xs"
                      checked={sel.includes(f)}
                      onChange={(e) => setSel(e.currentTarget.checked ? [...sel, f] : sel.filter((x) => x !== f))}
                      aria-label={f}
                    />
                  </Table.Td>
                  <Table.Td>
                    <Code fz="xs">{f}</Code>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </ScrollArea.Autosize>
        <Radio.Group value={action} onChange={(v) => setAction(v as "adopt" | "quarantine")}>
          <Stack gap={4}>
            <Radio
              value="adopt"
              label={t("recovery.adopt")}
              description={t("recovery.adoptHint")}
            />
            <Radio
              value="quarantine"
              label={t("recovery.quarantine")}
              description={t("recovery.quarantineHint")}
            />
          </Stack>
        </Radio.Group>
        <Textarea
          label={t("recovery.reason")}
          description={t("recovery.reasonHint")}
          autosize
          minRows={2}
          value={reason}
          onChange={(e) => setReason(e.currentTarget.value)}
        />
        <ReauthPassword label={t("yourPassword")} value={password} onChange={setPassword} />
        <Group justify="flex-end">
          <Button
            color={action === "quarantine" ? "orange" : undefined}
            loading={busy}
            disabled={sel.length === 0 || reason.trim().length < 10 || !password}
            onClick={() => void send()}
          >
            {t(action === "adopt" ? "recovery.adoptN" : "recovery.quarantineN", { n: sel.length })}
          </Button>
        </Group>
      </Stack>
    </Card>
  );
}

// Historia obsługi niezgodności.
export function RecoveryTable({ items }: { items: ArchiveRecovery[] }) {
  const { t } = useTranslation("archive");
  return (
    <Table.ScrollContainer minWidth={820}>
      <Table striped verticalSpacing="xs">
        <Table.Thead>
          <Table.Tr style={{ whiteSpace: "nowrap" }}>
            <Table.Th>#</Table.Th>
            <Table.Th>{t("col.requested")}</Table.Th>
            <Table.Th>{t("col.kind")}</Table.Th>
            <Table.Th>{t("col.who")}</Table.Th>
            <Table.Th>{t("col.cause")}</Table.Th>
            <Table.Th>{t("verif.result")}</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {items.map((r) => (
            <Table.Tr key={r.id}>
              <Table.Td>{r.id}</Table.Td>
              <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(r.requested_at)}</Table.Td>
              <Table.Td>
                <Badge variant="light" color={r.kind === "quarantine" ? "orange" : r.kind === "restore" ? "grape" : "blue"}>
                  {recoveryKindLabels[r.kind]}
                </Badge>
                {r.verification_id ? (
                  <Text size="xs" c="dimmed">
                    {t("recovery.verification", { id: r.verification_id })}
                  </Text>
                ) : null}
              </Table.Td>
              <Table.Td>{r.requested_by}</Table.Td>
              <Table.Td maw={320}>
                <Text size="sm">{r.reason}</Text>
                {r.window_from && r.window_to && (
                  <Text size="xs" c="dimmed">
                    {t("recovery.window", { from: formatDate(r.window_from), to: formatDate(r.window_to) })}
                  </Text>
                )}
              </Table.Td>
              <Table.Td maw={380}>
                <Badge
                  variant="light"
                  color={!r.processed_at ? "gray" : r.ok === false ? "red" : r.result?.rejected.length ? "orange" : "green"}
                >
                  {!r.processed_at ? t("recovery.state.waiting") : r.ok === false ? t("recovery.state.error") : t("recovery.state.done")}
                </Badge>{" "}
                <Text span size="sm">
                  {recoverySummary(r)}
                </Text>
                {r.processed_at && (
                  <Text size="xs" c="dimmed">
                    {formatDate(r.processed_at)}
                  </Text>
                )}
                {!!r.result?.rejected.length && (
                  <List size="xs" mt={4}>
                    {r.result.rejected.slice(0, 10).map((x) => (
                      <List.Item key={x.path}>
                        <Code fz="xs">{x.path}</Code>: {x.reason}
                      </List.Item>
                    ))}
                  </List>
                )}
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}
