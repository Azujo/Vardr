import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Code,
  CopyButton,
  Group,
  List,
  Modal,
  NumberInput,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCheck, IconCopy, IconDownload, IconKey, IconPlus } from "@tabler/icons-react";
import { enrollApi, formatDate, groupsApi, type AgentGroup, type AgentProfile, type EnrollToken } from "../api";
import { useAuth } from "../auth";

const profileLabels: Record<AgentProfile, string> = {
  workstation: "Stacja robocza",
  server: "Serwer",
  dc: "Kontroler domeny",
};

const validity = [
  { value: "24", label: "1 dzień" },
  { value: "168", label: "7 dni" },
  { value: "720", label: "30 dni" },
  { value: "2160", label: "90 dni" },
];

function tokenState(t: EnrollToken): { label: string; color: string } {
  if (t.revoked_at) return { label: "unieważniony", color: "gray" };
  if (new Date(t.expires_at) < new Date()) return { label: "wygasł", color: "gray" };
  if (t.max_uses > 0 && t.uses >= t.max_uses) return { label: "wykorzystany", color: "gray" };
  return { label: "aktywny", color: "green" };
}

function msg(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

// Sekret tokenu pokazywany jeden raz, z paczką i poleceniem do wdrożenia masowego.
function SecretModal({ data, server, onClose }: { data: { token: EnrollToken; secret: string } | null; server: string; onClose: () => void }) {
  const [busy, setBusy] = useState(false);
  if (!data) return null;
  const cmd = `siem_agent.exe install -server ${server || location.hostname} -token ${data.secret}`;
  const download = async () => {
    setBusy(true);
    try {
      await enrollApi.downloadPackage(data.secret);
    } catch (e) {
      notifications.show({ color: "red", message: msg(e) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal opened onClose={onClose} title={`Token: ${data.token.name}`} size="lg" centered>
      <Stack>
        <Alert color="yellow" title="Token widzisz tylko teraz">
          Panel przechowuje wyłącznie jego skrót. Pobierz paczkę albo skopiuj token teraz – później można go tylko
          unieważnić i utworzyć nowy.
        </Alert>
        <Group wrap="nowrap" align="flex-start">
          <Code block style={{ flex: 1, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
            {data.secret}
          </Code>
          <CopyButton value={data.secret}>
            {({ copied, copy }) => (
              <Button variant="default" leftSection={copied ? <IconCheck size={16} /> : <IconCopy size={16} />} onClick={copy}>
                {copied ? "Skopiowano" : "Kopiuj"}
              </Button>
            )}
          </CopyButton>
        </Group>
        <Button leftSection={<IconDownload size={18} />} loading={busy} onClick={() => void download()}>
          Pobierz paczkę instalacyjną (ZIP)
        </Button>
        <Text size="sm" c="dimmed">
          Paczka: program agenta, certyfikat CA, adres serwera, token i install.cmd – <b>bez klucza prywatnego</b>.
          Agent wygeneruje klucz na komputerze i zarejestruje się sam.
        </Text>
        <div>
          <Text size="sm" fw={500} mb={4}>
            Wdrożenie masowe (GPO, Intune, SCCM) – polecenie uruchamiane jako SYSTEM lub administrator:
          </Text>
          <Group wrap="nowrap" align="flex-start">
            <Code block style={{ flex: 1, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {cmd}
            </Code>
            <CopyButton value={cmd}>
              {({ copied, copy }) => (
                <Button variant="default" onClick={copy}>
                  {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                </Button>
              )}
            </CopyButton>
          </Group>
        </div>
        <Button variant="default" onClick={onClose}>
          Gotowe
        </Button>
      </Stack>
    </Modal>
  );
}

export default function DeployPage() {
  const { user } = useAuth();
  const [tokens, setTokens] = useState<EnrollToken[]>([]);
  const [enabled, setEnabled] = useState(true);
  const [server, setServer] = useState("");
  const [error, setError] = useState("");
  const [open, setOpen] = useState(false);
  const [secret, setSecret] = useState<{ token: EnrollToken; secret: string } | null>(null);
  const [form, setForm] = useState({ name: "", groupId: "", hours: "168", maxUses: 0 });
  const [groups, setGroups] = useState<AgentGroup[]>([]);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    enrollApi
      .list()
      .then((r) => {
        setTokens(r.tokens);
        setEnabled(r.enabled);
        setServer(r.public_server);
      })
      .catch((e) => setError(msg(e)));
  }, []);
  useEffect(() => {
    if (user?.role === "admin") load();
  }, [load, user]);
  useEffect(() => {
    groupsApi
      .list()
      .then((r) => {
        setGroups(r.groups);
        const def = r.groups.find((g) => g.is_default);
        if (def) setForm((f) => (f.groupId ? f : { ...f, groupId: String(def.id) }));
      })
      .catch(() => setGroups([]));
  }, []);

  if (user?.role !== "admin") {
    return (
      <Alert color="blue" title="Bifröst – wdrażanie agentów">
        Tokeny rejestracyjne i paczki instalacyjne tworzy administrator.
      </Alert>
    );
  }

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const g = groups.find((x) => String(x.id) === form.groupId);
      const res = await enrollApi.create({
        name: form.name,
        profile: g?.profile ?? "workstation",
        group_id: g?.id,
        valid_hours: Number(form.hours),
        max_uses: form.maxUses,
      });
      setOpen(false);
      setForm({ ...form, name: "", hours: "168", maxUses: 0 });
      setSecret(res);
      load();
    } catch (err) {
      notifications.show({ color: "red", message: msg(err) });
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (t: EnrollToken) => {
    if (!window.confirm(`Unieważnić token „${t.name}”? Zarejestrowani nim agenci działają dalej.`)) return;
    try {
      await enrollApi.revoke(t.id);
      load();
    } catch (e) {
      notifications.show({ color: "red", message: msg(e) });
    }
  };

  return (
    <Stack>
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>Bifröst – wdrażanie agentów</Title>
          <Text c="dimmed" size="sm">
            Token rejestracyjny pozwala zainstalować agentów bez przygotowywania certyfikatów dla każdego komputera.
          </Text>
        </div>
        <Button leftSection={<IconPlus size={18} />} onClick={() => setOpen(true)} disabled={!enabled}>
          Nowy token
        </Button>
      </Group>
      {!enabled && (
        <Alert color="orange" title="Rejestracja wyłączona">
          Brak CA agentów na serwerze. Utwórz je poleceniem <Code>siem-pki agents-ca</Code> i skopiuj agents-ca.crt oraz
          agents-ca.key do katalogu certs stosu.
        </Alert>
      )}
      {error && <Alert color="red">{error}</Alert>}

      <Alert color="blue" variant="light" title="Jak to działa">
        <List size="sm" spacing={2}>
          <List.Item>Tworzysz token dla grupy komputerów (profil zdarzeń, ważność, limit instalacji).</List.Item>
          <List.Item>Pobierasz paczkę ZIP albo kopiujesz polecenie do GPO lub Intune.</List.Item>
          <List.Item>
            Agent generuje klucz <b>na komputerze</b>, rejestruje się tokenem i dostaje certyfikat na 90 dni – odnawia go sam.
          </List.Item>
          <List.Item>Po wdrożeniu unieważnij token. Zgubiony komputer: Huginn → agent → „Unieważnij certyfikat”.</List.Item>
        </List>
      </Alert>

      <Table.ScrollContainer minWidth={760}>
        <Table striped verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Nazwa</Table.Th>
              <Table.Th>Grupa / profil</Table.Th>
              <Table.Th>Instalacje</Table.Th>
              <Table.Th>Ważny do</Table.Th>
              <Table.Th>Utworzył</Table.Th>
              <Table.Th>Stan</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {tokens.map((t) => {
              const s = tokenState(t);
              return (
                <Table.Tr key={t.id}>
                  <Table.Td>
                    <Group gap={6} wrap="nowrap">
                      <IconKey size={16} opacity={0.6} />
                      <Text fw={500}>{t.name}</Text>
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    {groups.find((g) => g.id === t.group_id)?.name ?? "Domyślna"}
                    <Text size="xs" c="dimmed">
                      {profileLabels[t.profile] ?? t.profile}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    {t.uses} / {t.max_uses === 0 ? "∞" : t.max_uses}
                  </Table.Td>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(t.expires_at)}</Table.Td>
                  <Table.Td>{t.created_by || "—"}</Table.Td>
                  <Table.Td>
                    <Badge color={s.color} variant="light">
                      {s.label}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    {s.label === "aktywny" && (
                      <Button size="xs" variant="subtle" color="red" onClick={() => void revoke(t)}>
                        Unieważnij
                      </Button>
                    )}
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      {tokens.length === 0 && (
        <Text c="dimmed" size="sm">
          Brak tokenów.
        </Text>
      )}

      <Modal opened={open} onClose={() => setOpen(false)} title="Nowy token rejestracyjny" centered>
        <form onSubmit={create}>
          <Stack>
            <TextInput
              label="Nazwa"
              description="np. „Księgowość – stacje” albo „Serwery IIS”"
              required
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.currentTarget.value })}
            />
            <Select
              label="Grupa agentów"
              description="Zarejestrowani agenci trafią do tej grupy (profil zdarzeń i limity)"
              data={groups.map((g) => ({ value: String(g.id), label: `${g.name} – ${profileLabels[g.profile]}` }))}
              value={form.groupId}
              allowDeselect={false}
              onChange={(v) => v && setForm({ ...form, groupId: v })}
            />
            <Select
              label="Ważność tokenu"
              data={validity}
              value={form.hours}
              allowDeselect={false}
              onChange={(v) => v && setForm({ ...form, hours: v })}
            />
            <NumberInput
              label="Limit instalacji"
              description="0 = bez limitu (np. do wdrożenia przez GPO)"
              min={0}
              max={100000}
              value={form.maxUses}
              onChange={(v) => setForm({ ...form, maxUses: Number(v) || 0 })}
            />
            <Button type="submit" loading={busy}>
              Utwórz token
            </Button>
          </Stack>
        </form>
      </Modal>
      <SecretModal data={secret} server={server} onClose={() => setSecret(null)} />
    </Stack>
  );
}
