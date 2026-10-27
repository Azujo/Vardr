// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo, useState } from "react";
import {
  Alert as MAlert,
  Badge,
  Button,
  Checkbox,
  Group,
  List,
  Modal,
  Stack,
  Table,
  Text,
  TextInput,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconHistory, IconRefresh, IconSearch } from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import i18n from "../i18n";
import { ApiError, backupApi, formatBytes, formatDate, type BackupFile, type BackupPart, type BackupView } from "../api";
import { ReauthPassword } from "../sso";

// Przywracanie z kopii (Administracja → Kopie zapasowe → Przywracanie).
// Usługa kopii przygotowuje przywrócenie (kopia obecnego stanu, pobranie
// i sprawdzenie kopii), a restore.sh na serwerze przywraca wybrane części.

// Słowo potwierdzenia: serwer przyjmuje PRZYWRÓĆ albo RESTORE.
const confirmWord = () => i18n.t("backup:restore.word");

// Czas kopii z nazwy (vardr-RRRRMMDD-GGMM-k….tar.gpg, UTC; heimdall- sprzed zmiany nazwy).
function backupTime(name: string): string | undefined {
  const m = /^(?:vardr|heimdall)-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})-/.exec(name);
  return m ? `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:00Z` : undefined;
}

type Ask = (action: "list" | "inspect", file?: { location: string; name: string }) => Promise<void>;

export default function RestorePanel({ view, ask }: { view: BackupView; ask: Ask }) {
  const { t } = useTranslation("backup");
  const st = view.state;
  const [target, setTarget] = useState<BackupFile | null>(null);
  const restoring = st.requests.find((r) => r.action === "restore" && !r.done_at);
  const lastRestore = st.requests.find((r) => r.action === "restore" && r.done_at);
  const inspecting = new Set(
    st.requests.filter((r) => r.action === "inspect" && !r.done_at).map((r) => `${r.params?.location}/${r.params?.name}`),
  );
  const listing = st.requests.some((r) => r.action === "list" && !r.done_at);
  // Ta sama kopia lokalnie i w miejscu docelowym – jeden wiersz (lokalna wystarczy).
  const files = useMemo(() => {
    const local = new Set(st.files.filter((f) => f.location === "local").map((f) => f.name));
    return st.files.filter((f) => f.location === "local" || !local.has(f.name));
  }, [st.files]);

  return (
    <Stack>
      <MAlert color="gray" title={t("restore.how")}>
        <List size="sm" spacing={2}>
          {[1, 2, 3, 4].map((i) => (
            <List.Item key={i}>{t(`restore.how${i}`)}</List.Item>
          ))}
        </List>
      </MAlert>

      {restoring && (
        <MAlert color="red" title={t("restore.inProgress")}>
          {restoring.message || t("restore.preparing")} {t("restore.requestedBy", { by: restoring.requested_by, date: formatDate(restoring.requested_at) })}
        </MAlert>
      )}
      {!restoring && lastRestore && (
        <MAlert color={lastRestore.ok ? "green" : "red"} title={lastRestore.ok ? t("restore.last") : t("restore.lastFailed")}>
          {lastRestore.message} ({lastRestore.requested_by}, {formatDate(lastRestore.done_at)})
        </MAlert>
      )}

      <Group>
        <Button size="xs" variant="default" leftSection={<IconRefresh size={14} />} loading={listing} onClick={() => void ask("list")}>
          {t("restore.refresh")}
        </Button>
        <Text size="xs" c="dimmed">
          {t("restore.refreshHint")}
        </Text>
      </Group>

      {files.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("restore.empty")}
        </Text>
      ) : (
        <Table.ScrollContainer minWidth={760}>
          <Table fz="sm" verticalSpacing={4} striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("restore.col.from")}</Table.Th>
                <Table.Th>{t("restore.col.where")}</Table.Th>
                <Table.Th>{t("history.col.size")}</Table.Th>
                <Table.Th>{t("include.title")}</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {files.map((f) => {
                const key = `${f.location}/${f.name}`;
                return (
                  <Table.Tr key={key}>
                    <Table.Td style={{ whiteSpace: "nowrap" }} title={f.name}>
                      {formatDate(backupTime(f.name) ?? f.modified)}
                    </Table.Td>
                    <Table.Td>{f.location === "local" ? t("restore.server") : t("restore.target")}</Table.Td>
                    <Table.Td>{formatBytes(f.size_bytes)}</Table.Td>
                    <Table.Td>
                      {f.contents ? (
                        <Group gap={4}>
                          {f.contents.map((p) => (
                            <Badge key={p} size="xs" variant="light">
                              {t(`restore.part.${p}`)}
                            </Badge>
                          ))}
                        </Group>
                      ) : f.note ? (
                        <Text size="xs" c="red">
                          {f.note}
                        </Text>
                      ) : (
                        <Text size="xs" c="dimmed">
                          {t("restore.unchecked")}
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Group gap={4} justify="flex-end" wrap="nowrap">
                        <Button
                          size="compact-xs"
                          variant="subtle"
                          leftSection={<IconSearch size={12} />}
                          loading={inspecting.has(key)}
                          disabled={!view.online}
                          onClick={() => void ask("inspect", { location: f.location, name: f.name })}
                        >
                          {t("restore.inspect")}
                        </Button>
                        <Button
                          size="compact-xs"
                          variant="light"
                          color="red"
                          leftSection={<IconHistory size={12} />}
                          disabled={!f.contents || !!restoring || !view.online}
                          onClick={() => setTarget(f)}
                        >
                          {t("restore.restoreEllipsis")}
                        </Button>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}

      {target && <RestoreModal file={target} onClose={() => setTarget(null)} />}
    </Stack>
  );
}

function RestoreModal({ file, onClose }: { file: BackupFile; onClose: () => void }) {
  const { t } = useTranslation("backup");
  const have = file.contents ?? [];
  // Baza i konfiguracja razem (hasła ról bazy są w .env).
  const both = have.includes("saga") && have.includes("config");
  const [core, setCore] = useState(have.includes("saga") || have.includes("config"));
  const [grafana, setGrafana] = useState(false);
  const [safety, setSafety] = useState(true);
  const [confirm, setConfirm] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  const parts: BackupPart[] = [
    ...(core ? (have.filter((p) => p === "saga" || p === "config") as BackupPart[]) : []),
    ...(grafana ? (["grafana"] as BackupPart[]) : []),
  ];
  const when = formatDate(backupTime(file.name) ?? file.modified);

  const submit = async () => {
    setBusy(true);
    try {
      await backupApi.restore({ location: file.location, name: file.name }, parts, safety, confirm, password);
      notifications.show({ color: "orange", autoClose: false, message: t("restore.requested") });
      onClose();
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) setPassword("");
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal opened onClose={onClose} title={t("restore.title", { when })} size="lg" centered>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Stack gap="sm">
          <Text size="xs" c="dimmed">
            {file.name} ({file.location === "local" ? t("restore.onServer") : t("restore.atTarget")})
          </Text>
          {(have.includes("saga") || have.includes("config")) && (
            <Checkbox
              label={both ? t("restore.both") : have.includes("saga") ? t("include.saga") : t("include.config")}
              description={both ? t("restore.bothHint") : undefined}
              checked={core}
              onChange={(e) => setCore(e.currentTarget.checked)}
            />
          )}
          {have.includes("grafana") && (
            <Checkbox label={t("include.grafana")} checked={grafana} onChange={(e) => setGrafana(e.currentTarget.checked)} />
          )}
          <Checkbox
            label={t("restore.safety")}
            description={t("restore.safetyHint")}
            checked={safety}
            onChange={(e) => setSafety(e.currentTarget.checked)}
          />
          {core && (
            <MAlert color="red">
              <List size="sm" spacing={2}>
                <List.Item>{t("restore.warn1", { when })}</List.Item>
                <List.Item>{t("restore.warn2")}</List.Item>
                <List.Item>{t("restore.warn3")}</List.Item>
                <List.Item>{t("restore.warn4")}</List.Item>
              </List>
            </MAlert>
          )}
          <TextInput
            label={t("restore.typeWord", { word: confirmWord() })}
            value={confirm}
            onChange={(e) => setConfirm(e.currentTarget.value)}
            autoComplete="off"
          />
          <ReauthPassword
            label={t("yourPassword")}
            required
            value={password}
            onChange={setPassword}
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              {t("back")}
            </Button>
            <Button type="submit" color="red" loading={busy} disabled={parts.length === 0 || confirm.trim() !== confirmWord() || !password}>
              {t("restore.restore")}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
