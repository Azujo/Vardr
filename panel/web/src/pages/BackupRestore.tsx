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
  PasswordInput,
  Stack,
  Table,
  Text,
  TextInput,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconHistory, IconRefresh, IconSearch } from "@tabler/icons-react";
import { ApiError, backupApi, formatBytes, formatDate, type BackupFile, type BackupPart, type BackupView } from "../api";

// Przywracanie z kopii (Administracja → Kopie zapasowe → Przywracanie).
// Usługa kopii przygotowuje przywrócenie (kopia obecnego stanu, pobranie
// i sprawdzenie kopii), a restore.sh na serwerze przywraca wybrane części.

const partLabels: Record<BackupPart, string> = { saga: "baza Saga", config: "konfiguracja", grafana: "Grafana" };
const confirmWord = "PRZYWRÓĆ";

// Czas kopii z nazwy (vardr-RRRRMMDD-GGMM-k….tar.gpg, UTC; heimdall- sprzed zmiany nazwy).
function backupTime(name: string): string | undefined {
  const m = /^(?:vardr|heimdall)-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})-/.exec(name);
  return m ? `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:00Z` : undefined;
}

type Ask = (action: "list" | "inspect", file?: { location: string; name: string }) => Promise<void>;

export default function RestorePanel({ view, ask }: { view: BackupView; ask: Ask }) {
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
      <MAlert color="gray" title="Jak działa przywracanie">
        <List size="sm" spacing={2}>
          <List.Item>Wybierasz kopię i części do przywrócenia; najpierw sprawdź jej zawartość (odszyfrowanie hasłem kopii).</List.Item>
          <List.Item>Usługa kopii robi kopię obecnego stanu (można z niej wrócić), pobiera wybraną kopię z miejsca docelowego.</List.Item>
          <List.Item>
            Serwer w ciągu minuty zatrzymuje usługi korzystające z bazy, przywraca wybrane części i uruchamia stos – panel jest wtedy
            przez chwilę niedostępny, a po przywróceniu bazy trzeba się zalogować ponownie.
          </List.Item>
          <List.Item>Archiwum NIS2 przywraca się na czystym serwerze poleceniem restore.sh (docs/operacje.md).</List.Item>
        </List>
      </MAlert>

      {restoring && (
        <MAlert color="red" title="Przywracanie w toku">
          {restoring.message || "Usługa kopii przygotowuje przywrócenie…"} Zlecił {restoring.requested_by}, {formatDate(restoring.requested_at)}.
        </MAlert>
      )}
      {!restoring && lastRestore && (
        <MAlert color={lastRestore.ok ? "green" : "red"} title={lastRestore.ok ? "Ostatnie przywrócenie" : "Ostatnie przywrócenie nieudane"}>
          {lastRestore.message} ({lastRestore.requested_by}, {formatDate(lastRestore.done_at)})
        </MAlert>
      )}

      <Group>
        <Button size="xs" variant="default" leftSection={<IconRefresh size={14} />} loading={listing} onClick={() => void ask("list")}>
          Odśwież listę kopii
        </Button>
        <Text size="xs" c="dimmed">
          Lista odświeża się sama co 15 minut i po każdej kopii.
        </Text>
      </Group>

      {files.length === 0 ? (
        <Text size="sm" c="dimmed">
          Brak kopii na liście.
        </Text>
      ) : (
        <Table.ScrollContainer minWidth={760}>
          <Table fz="sm" verticalSpacing={4} striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Kopia z</Table.Th>
                <Table.Th>Gdzie</Table.Th>
                <Table.Th>Rozmiar</Table.Th>
                <Table.Th>Zawartość</Table.Th>
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
                    <Table.Td>{f.location === "local" ? "serwer" : "miejsce docelowe"}</Table.Td>
                    <Table.Td>{formatBytes(f.size_bytes)}</Table.Td>
                    <Table.Td>
                      {f.contents ? (
                        <Group gap={4}>
                          {f.contents.map((p) => (
                            <Badge key={p} size="xs" variant="light">
                              {partLabels[p]}
                            </Badge>
                          ))}
                        </Group>
                      ) : f.note ? (
                        <Text size="xs" c="red">
                          {f.note}
                        </Text>
                      ) : (
                        <Text size="xs" c="dimmed">
                          niesprawdzona
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
                          sprawdź
                        </Button>
                        <Button
                          size="compact-xs"
                          variant="light"
                          color="red"
                          leftSection={<IconHistory size={12} />}
                          disabled={!f.contents || !!restoring || !view.online}
                          onClick={() => setTarget(f)}
                        >
                          przywróć…
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
      const r = await backupApi.restore({ location: file.location, name: file.name }, parts, safety, confirm, password);
      notifications.show({ color: "orange", autoClose: false, message: r.message });
      onClose();
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) setPassword("");
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal opened onClose={onClose} title={`Przywrócenie z kopii z ${when}`} size="lg" centered>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Stack gap="sm">
          <Text size="xs" c="dimmed">
            {file.name} ({file.location === "local" ? "na serwerze" : "w miejscu docelowym"})
          </Text>
          {(have.includes("saga") || have.includes("config")) && (
            <Checkbox
              label={both ? "Baza Saga i konfiguracja serwera" : have.includes("saga") ? "Baza Saga" : "Konfiguracja serwera"}
              description={
                both
                  ? "przywracane razem – w .env są hasła ról bazy; konta, agenci, certyfikaty, alerty, polityki, ustawienia kopii, certs/ i .env"
                  : undefined
              }
              checked={core}
              onChange={(e) => setCore(e.currentTarget.checked)}
            />
          )}
          {have.includes("grafana") && (
            <Checkbox label="Dane Grafany" checked={grafana} onChange={(e) => setGrafana(e.currentTarget.checked)} />
          )}
          <Checkbox
            label="Najpierw kopia obecnego stanu (zalecane)"
            description="pozwala wrócić do stanu sprzed przywrócenia"
            checked={safety}
            onChange={(e) => setSafety(e.currentTarget.checked)}
          />
          {core && (
            <MAlert color="red">
              <List size="sm" spacing={2}>
                <List.Item>Baza wróci do stanu z {when}: alerty, zmiany ustawień, konta i agenci zarejestrowani później znikną.</List.Item>
                <List.Item>Agenci zarejestrowani po tej dacie muszą zarejestrować się ponownie.</List.Item>
                <List.Item>Panel będzie przez chwilę niedostępny; po przywróceniu zaloguj się ponownie (hasłem z dnia kopii).</List.Item>
                <List.Item>Zdarzenia w ClickHouse i archiwum NIS2 nie są zmieniane.</List.Item>
              </List>
            </MAlert>
          )}
          <TextInput
            label={`Wpisz ${confirmWord}, aby potwierdzić`}
            value={confirm}
            onChange={(e) => setConfirm(e.currentTarget.value)}
            autoComplete="off"
          />
          <PasswordInput
            label="Twoje hasło"
            required
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.currentTarget.value)}
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Wróć
            </Button>
            <Button type="submit" color="red" loading={busy} disabled={parts.length === 0 || confirm.trim() !== confirmWord || !password}>
              Przywróć
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
