// SPDX-License-Identifier: AGPL-3.0-or-later

// Zmiana zbiorcza reguł (włączenie, wyłączenie, tryb próbny, ustawienie
// z pliku) – zawsze z powodem i hasłem: hurtowe włączenie może zalać
// analityków alertami, a wyłączenie osłabia detekcję.
import { useState } from "react";
import { Alert as MAlert, Button, Group, Modal, PasswordInput, Stack, Text, Textarea } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useTranslation } from "react-i18next";
import i18n from "../i18n";
import { rulesApi, type BulkRuleAction } from "../api";

// Nazwy akcji tłumaczone przy odczycie (rules: bulk.<akcja>).
export const bulkLabels = Object.defineProperties({} as Record<BulkRuleAction, string>, {
  trial: { enumerable: true, get: () => i18n.t("rules:bulk.trial") },
  enable: { enumerable: true, get: () => i18n.t("rules:bulk.enable") },
  disable: { enumerable: true, get: () => i18n.t("rules:bulk.disable") },
  file: { enumerable: true, get: () => i18n.t("rules:bulk.file") },
});

const bulkColors: Record<BulkRuleAction, string> = { trial: "yellow", enable: "orange", disable: "red", file: "gray" };

export default function RuleBulkModal({
  ids,
  action,
  onClose,
  onDone,
}: {
  ids: string[];
  action: BulkRuleAction | null;
  onClose: () => void;
  onDone: () => void;
}) {
  const { t } = useTranslation("rules");
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const apply = async () => {
    if (!action) return;
    setBusy(true);
    try {
      const r = await rulesApi.bulk(ids, action, reason, password);
      notifications.show({ color: "green", message: t("bulk.done", { changed: r.changed, skipped: r.skipped }) });
      setReason("");
      setPassword("");
      onDone();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal opened={!!action} onClose={onClose} title={action ? t("bulk.title", { action: bulkLabels[action], count: ids.length }) : ""} centered>
      {action && (
        <Stack>
          <MAlert color={bulkColors[action]}>{t(`bulk.info.${action}`)}</MAlert>
          <Text size="sm" c="dimmed">
            {t("bulk.skipInfo")}
          </Text>
          <Textarea
            label={t("reason")}
            description={t("bulk.reasonHint")}
            autosize
            minRows={2}
            value={reason}
            onChange={(e) => setReason(e.currentTarget.value)}
          />
          <PasswordInput label={t("yourPassword")} value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
          <Group justify="flex-end">
            <Button
              color={action === "disable" ? "red" : undefined}
              loading={busy}
              disabled={reason.trim().length < 3 || !password}
              onClick={() => void apply()}
            >
              {bulkLabels[action]} ({ids.length})
            </Button>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}
