// SPDX-License-Identifier: AGPL-3.0-or-later

// Moje konto → Bezpieczeństwo: klucze bezpieczeństwa i passkeys (WebAuthn)
// – drugi składnik obok aplikacji TOTP, wybierany przy logowaniu.
import { useCallback, useEffect, useState } from "react";
import { ActionIcon, Alert, Badge, Button, Card, Group, Modal, PasswordInput, Stack, Table, Text, TextInput, Tooltip } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconKey, IconTrash } from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import { api, formatDate, type WebAuthnKey, type WebAuthnStatus } from "../api";
import { createCredential, webauthnCancelled, webauthnSupported } from "../webauthn";

type Dialog = { kind: "add" } | { kind: "remove"; key: WebAuthnKey };

export default function SecurityKeysCard({ totp }: { totp: boolean }) {
  const { t } = useTranslation("account");
  const [st, setSt] = useState<WebAuthnStatus | null>(null);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api.webauthnStatus().then(setSt, () => setSt(null));
  }, []);
  useEffect(load, [load]);

  if (!st?.available) return null;
  const supported = webauthnSupported();

  const open = (d: Dialog) => {
    setPassword("");
    setName("");
    setDialog(d);
  };

  const add = async () => {
    setBusy(true);
    try {
      const { publicKey } = await api.webauthnBegin(password);
      const r = await createCredential(publicKey);
      await api.webauthnConfirm(name.trim(), r);
      notifications.show({ color: "green", message: t("security.keys.added", { name: name.trim() }) });
      setDialog(null);
      load();
    } catch (e) {
      notifications.show({
        color: "red",
        message: webauthnCancelled(e) ? t("security.keys.cancelled") : e instanceof Error ? e.message : String(e),
      });
    } finally {
      setBusy(false);
    }
  };

  const remove = async (k: WebAuthnKey) => {
    setBusy(true);
    try {
      await api.webauthnDelete(k.id, password);
      setDialog(null);
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card withBorder>
      <Stack gap="xs">
        <Group justify="space-between">
          <Group gap="xs">
            <IconKey color={st.keys.length ? "var(--mantine-color-green-6)" : "var(--mantine-color-gray-6)"} />
            <Text fw={500}>{t("security.keys.title")}</Text>
          </Group>
          <Badge color={st.keys.length ? "green" : "gray"}>{st.keys.length}</Badge>
        </Group>
        <Text size="sm" c="dimmed">
          {t("security.keys.intro")}
        </Text>
        {!totp && <Alert color="gray">{t("security.keys.totpFirst")}</Alert>}
        {st.rp_error && <Alert color="orange">{t("security.keys.needsName")}</Alert>}
        {!supported && <Alert color="orange">{t("security.keys.unsupported")}</Alert>}
        {st.keys.length > 0 && (
          <Table>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("security.keys.name")}</Table.Th>
                <Table.Th>{t("security.keys.addedAt")}</Table.Th>
                <Table.Th>{t("security.keys.lastUsed")}</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {st.keys.map((k) => (
                <Table.Tr key={k.id}>
                  <Table.Td>
                    {k.name}
                    {k.rp_id !== st.rp_id && (
                      <Text size="xs" c="orange">
                        {t("security.keys.otherAddress", { rp: k.rp_id })}
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>{formatDate(k.created_at)}</Table.Td>
                  <Table.Td>{k.last_used_at ? formatDate(k.last_used_at) : "–"}</Table.Td>
                  <Table.Td>
                    <Tooltip label={t("security.keys.remove")}>
                      <ActionIcon variant="subtle" color="red" onClick={() => open({ kind: "remove", key: k })} aria-label={t("security.keys.remove")}>
                        <IconTrash size={16} />
                      </ActionIcon>
                    </Tooltip>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
        <Group>
          <Button variant="light" leftSection={<IconKey size={16} />} disabled={!totp || !!st.rp_error || !supported} onClick={() => open({ kind: "add" })}>
            {t("security.keys.add")}
          </Button>
        </Group>
      </Stack>

      <Modal
        opened={!!dialog}
        onClose={() => setDialog(null)}
        title={dialog?.kind === "add" ? t("security.keys.add") : t("security.keys.remove")}
        centered
      >
        {dialog?.kind === "add" && (
          <Stack>
            <TextInput
              label={t("security.keys.name")}
              description={t("security.keys.nameHint")}
              maxLength={64}
              value={name}
              onChange={(e) => setName(e.currentTarget.value)}
              autoFocus
            />
            <PasswordInput label={t("security.yourPassword")} value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
            <Text size="sm" c="dimmed">
              {t("security.keys.touch")}
            </Text>
            <Button loading={busy} disabled={!password || !name.trim()} onClick={() => void add()}>
              {t("security.keys.register")}
            </Button>
          </Stack>
        )}
        {dialog?.kind === "remove" && (
          <Stack>
            <Text size="sm">{t("security.keys.removeText", { name: dialog.key.name })}</Text>
            <PasswordInput label={t("security.yourPassword")} value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoFocus />
            <Button color="red" loading={busy} disabled={!password} onClick={() => void remove(dialog.key)}>
              {t("security.keys.remove")}
            </Button>
          </Stack>
        )}
      </Modal>
    </Card>
  );
}
