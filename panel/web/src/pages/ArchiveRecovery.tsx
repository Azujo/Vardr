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
  PasswordInput,
  Radio,
  ScrollArea,
  Stack,
  Table,
  Text,
  Textarea,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { ApiError, archiveApi, formatDate, type ArchiveRecovery, type ArchiveVerification } from "../api";

export const recoveryKindLabels: Record<ArchiveRecovery["kind"], string> = {
  restore: "po przywróceniu kopii",
  adopt: "przyjęcie do archiwum",
  quarantine: "kwarantanna",
};

export function recoverySummary(r: ArchiveRecovery): string {
  if (!r.processed_at) return "oczekuje na archiwizator";
  if (r.ok === false) return `nieudane: ${r.error}`;
  const res = r.result;
  if (!res) return "wykonane";
  const parts: string[] = [];
  if (res.manifests.length) parts.push(`przywrócone manifesty: ${res.manifests.length}`);
  if (res.segments.length) parts.push(`przyjęte segmenty: ${res.segments.length}`);
  if (res.quarantined.length) parts.push(`w kwarantannie: ${res.quarantined.length}`);
  if (res.rejected.length) parts.push(`odrzucone: ${res.rejected.length}`);
  return parts.join(", ") || "brak plików do uzgodnienia";
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
      const r = await archiveApi.recovery(action, sel, reason.trim(), password);
      notifications.show({ color: "green", message: r.message });
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
      <Alert color="blue" title={`Zlecenie #${pending.id} czeka na archiwizator`}>
        <Text size="sm">
          {recoveryKindLabels[pending.kind]} – {pending.paths.length} plików, zlecił {pending.requested_by}. Archiwizator wykona je w
          ciągu minuty i od razu zweryfikuje archiwum.
        </Text>
      </Alert>
    );
  }
  return (
    <Card withBorder>
      <Stack gap="xs">
        <Text fw={600}>Pliki nieznane spisowi ({files.length}) – decyzja administratora</Text>
        <Text size="sm" c="dimmed">
          Najczęstsza przyczyna: przywrócenie kopii bazy – spis wrócił do chwili zrzutu, a pliki zapisane później zostały na dysku.
          Wynik weryfikacji zostaje w historii bez zmian; decyzja jest osobnym wpisem (spis archiwum, plik w katalogu archiwum,
          audyt). Nic nie jest usuwane.
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
              label="Przyjmij do archiwum"
              description="archiwizator sprawdzi format i sumy SHA-256 każdej paczki (manifest – także ciągłość łańcucha); plik niezgodny zostanie odrzucony"
            />
            <Radio
              value="quarantine"
              label="Odłóż do kwarantanny"
              description="plik zostanie przeniesiony do katalogu quarantine/ w archiwum – zachowany, ale poza łańcuchem (np. pochodzenie niejasne)"
            />
          </Stack>
        </Radio.Group>
        <Textarea
          label="Przyczyna niezgodności"
          description="trafi do spisu archiwum i audytu, np. „przywrócenie kopii z 19.10 08:05 – segmenty zapisane między zrzutem a przywróceniem”"
          autosize
          minRows={2}
          value={reason}
          onChange={(e) => setReason(e.currentTarget.value)}
        />
        <PasswordInput label="Twoje hasło" value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
        <Group justify="flex-end">
          <Button
            color={action === "quarantine" ? "orange" : undefined}
            loading={busy}
            disabled={sel.length === 0 || reason.trim().length < 10 || !password}
            onClick={() => void send()}
          >
            {action === "adopt" ? "Przyjmij" : "Odłóż"} wybrane ({sel.length})
          </Button>
        </Group>
      </Stack>
    </Card>
  );
}

// Historia obsługi niezgodności.
export function RecoveryTable({ items }: { items: ArchiveRecovery[] }) {
  return (
    <Table.ScrollContainer minWidth={820}>
      <Table striped verticalSpacing="xs">
        <Table.Thead>
          <Table.Tr style={{ whiteSpace: "nowrap" }}>
            <Table.Th>#</Table.Th>
            <Table.Th>Zlecono</Table.Th>
            <Table.Th>Rodzaj</Table.Th>
            <Table.Th>Kto</Table.Th>
            <Table.Th>Przyczyna</Table.Th>
            <Table.Th>Wynik</Table.Th>
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
                    weryfikacja #{r.verification_id}
                  </Text>
                ) : null}
              </Table.Td>
              <Table.Td>{r.requested_by}</Table.Td>
              <Table.Td maw={320}>
                <Text size="sm">{r.reason}</Text>
                {r.window_from && r.window_to && (
                  <Text size="xs" c="dimmed">
                    okno: {formatDate(r.window_from)} – {formatDate(r.window_to)}
                  </Text>
                )}
              </Table.Td>
              <Table.Td maw={380}>
                <Badge
                  variant="light"
                  color={!r.processed_at ? "gray" : r.ok === false ? "red" : r.result?.rejected.length ? "orange" : "green"}
                >
                  {!r.processed_at ? "oczekuje" : r.ok === false ? "błąd" : "wykonane"}
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
