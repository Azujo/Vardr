// SPDX-License-Identifier: AGPL-3.0-or-later

// Zmiana zbiorcza reguł (włączenie, wyłączenie, tryb próbny, ustawienie
// z pliku) – zawsze z powodem i hasłem: hurtowe włączenie może zalać
// analityków alertami, a wyłączenie osłabia detekcję.
import { useState } from "react";
import { Alert as MAlert, Button, Group, Modal, PasswordInput, Stack, Text, Textarea } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { rulesApi, type BulkRuleAction } from "../api";

export const bulkLabels: Record<BulkRuleAction, string> = {
  trial: "Tryb próbny",
  enable: "Włącz",
  disable: "Wyłącz",
  file: "Ustawienie z pliku",
};

const bulkInfo: Record<BulkRuleAction, { color: string; text: string }> = {
  trial: {
    color: "yellow",
    text: "Reguły będą liczyć trafienia bez alertów i powiadomień (strona „Próby reguł”). Włączone reguły z zaznaczenia przestaną alarmować na czas próby.",
  },
  enable: {
    color: "orange",
    text: "Reguły zaczną tworzyć alerty i powiadomienia. Włączenie wielu reguł bez próby może zalać analityków fałszywymi alarmami.",
  },
  disable: { color: "red", text: "Wyłączone reguły nie wywołają alertów – także przy prawdziwym ataku." },
  file: { color: "gray", text: "Reguły wrócą do ustawienia z pliku (enabled w treści reguły); ustawienia z panelu znikną." },
};

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
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const apply = async () => {
    if (!action) return;
    setBusy(true);
    try {
      const r = await rulesApi.bulk(ids, action, reason, password);
      notifications.show({ color: "green", message: r.message });
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
    <Modal opened={!!action} onClose={onClose} title={action ? `${bulkLabels[action]} – zaznaczone reguły: ${ids.length}` : ""} centered>
      {action && (
        <Stack>
          <MAlert color={bulkInfo[action].color}>{bulkInfo[action].text}</MAlert>
          <Text size="sm" c="dimmed">
            Reguły, których zmiana nie dotyczy (np. już w tym stanie albo wbudowane), zostaną pominięte. Zmiana trafi do audytu,
            detektor zastosuje ją w ciągu 30 s.
          </Text>
          <Textarea
            label="Powód"
            description="np. ocena reguł SigmaHQ dla Windows przed włączeniem"
            autosize
            minRows={2}
            value={reason}
            onChange={(e) => setReason(e.currentTarget.value)}
          />
          <PasswordInput label="Twoje hasło" value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
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
