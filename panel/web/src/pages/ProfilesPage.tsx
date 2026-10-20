// Profile uprawnień: macierz moduł → poziom (brak, odczyt, test/eksport,
// zmiana). Profile wbudowane (administrator, analityk, obserwator) są stałe –
// można je skopiować jako punkt wyjścia. Zmiany z hasłem, w audycie.
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Group,
  Modal,
  PasswordInput,
  SegmentedControl,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCopy, IconPencil, IconPlus, IconTrash } from "@tabler/icons-react";
import { api, formatDate, type PermModule, type Permissions, type Profile } from "../api";
import { useAuth } from "../auth";

interface Draft {
  id: string;
  isNew: boolean;
  name: string;
  description: string;
  permissions: Permissions;
}

// slug: identyfikator profilu z nazwy (małe litery, cyfry, myślniki).
function slug(name: string): string {
  const map: Record<string, string> = { ą: "a", ć: "c", ę: "e", ł: "l", ń: "n", ó: "o", ś: "s", ź: "z", ż: "z" };
  return name
    .toLowerCase()
    .replace(/[ąćęłńóśźż]/g, (c) => map[c] ?? c)
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
}

function summary(p: Permissions, modules: PermModule[]): string {
  const parts = modules
    .filter((m) => p[m.key])
    .map((m) => `${m.label}: ${m.levels.find((l) => l.key === p[m.key])?.label ?? p[m.key]}`);
  return parts.length ? parts.join(" · ") : "brak dostępu";
}

export default function ProfilesPage() {
  const { can } = useAuth();
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [modules, setModules] = useState<PermModule[]>([]);
  const [editable, setEditable] = useState(false);
  const [error, setError] = useState("");
  const [draft, setDraft] = useState<Draft | null>(null);
  const [del, setDel] = useState<Profile | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const canEdit = can("users", "write") && editable;

  const load = useCallback(() => {
    Promise.all([api.profiles(), api.permissions()])
      .then(([p, m]) => {
        setProfiles(p.profiles);
        setEditable(p.editable);
        setModules(m.modules);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);
  useEffect(load, [load]);

  const taken = useMemo(() => new Set(profiles.map((p) => p.id)), [profiles]);
  const openDraft = (p: Profile | null, copy = false) => {
    setPassword("");
    if (!p) {
      setDraft({ id: "", isNew: true, name: "", description: "", permissions: {} });
    } else if (copy) {
      setDraft({ id: "", isNew: true, name: `${p.name} (kopia)`, description: p.description, permissions: { ...p.permissions } });
    } else {
      setDraft({ id: p.id, isNew: false, name: p.name, description: p.description, permissions: { ...p.permissions } });
    }
  };
  const draftID = draft ? (draft.isNew ? slug(draft.name) : draft.id) : "";
  const idProblem = draft?.isNew && draftID.length < 2 ? "nazwa za krótka" : draft?.isNew && taken.has(draftID) ? "profil o tym identyfikatorze już istnieje" : "";

  const save = async () => {
    if (!draft) return;
    setBusy(true);
    try {
      await api.saveProfile(draftID, { name: draft.name, description: draft.description, permissions: draft.permissions, password });
      notifications.show({ color: "green", message: `Zapisano profil „${draft.name}”` });
      setDraft(null);
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if (!del) return;
    setBusy(true);
    try {
      await api.deleteProfile(del.id, password);
      notifications.show({ color: "green", message: `Usunięto profil „${del.name}”` });
      setDel(null);
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack>
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>Profile uprawnień</Title>
          <Text c="dimmed" size="sm" maw={820}>
            Profil określa, do których modułów panelu konto ma dostęp i na jakim poziomie (wyższy obejmuje niższe). Konto ma
            jeden profil (wybierany w Użytkownikach). Profil z prawem zmiany w module „Użytkownicy i bezpieczeństwo” to
            administrator panelu – panel nie pozwoli zostać bez żadnego aktywnego.
          </Text>
        </div>
        {canEdit && (
          <Button leftSection={<IconPlus size={16} />} onClick={() => openDraft(null)}>
            Nowy profil
          </Button>
        )}
      </Group>
      {error && <Alert color="red">{error}</Alert>}
      <Table.ScrollContainer minWidth={900}>
        <Table striped verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Profil</Table.Th>
              <Table.Th>Uprawnienia</Table.Th>
              <Table.Th>Konta</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {profiles.map((p) => (
              <Table.Tr key={p.id}>
                <Table.Td maw={260}>
                  <Group gap={6}>
                    <Text fw={500}>{p.name}</Text>
                    {p.builtin && (
                      <Badge size="xs" variant="outline">
                        wbudowany
                      </Badge>
                    )}
                    {p.admin && (
                      <Badge size="xs" color="grape">
                        administrator
                      </Badge>
                    )}
                  </Group>
                  <Text size="xs" c="dimmed">
                    {p.description}
                  </Text>
                  {!p.builtin && p.updated_by && (
                    <Text size="xs" c="dimmed">
                      zmienił {p.updated_by}, {formatDate(p.updated_at)}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td maw={520}>
                  <Text size="xs">{summary(p.permissions, modules)}</Text>
                </Table.Td>
                <Table.Td>{p.users}</Table.Td>
                <Table.Td>
                  {canEdit && (
                    <Group gap={4} wrap="nowrap">
                      {!p.builtin && (
                        <Tooltip label="Edytuj">
                          <Button size="compact-sm" variant="subtle" onClick={() => openDraft(p)}>
                            <IconPencil size={16} />
                          </Button>
                        </Tooltip>
                      )}
                      <Tooltip label="Kopiuj jako nowy">
                        <Button size="compact-sm" variant="subtle" onClick={() => openDraft(p, true)}>
                          <IconCopy size={16} />
                        </Button>
                      </Tooltip>
                      {!p.builtin && (
                        <Tooltip label={p.users > 0 ? "profil ma przypisane konta" : "Usuń"}>
                          <Button
                            size="compact-sm"
                            variant="subtle"
                            color="red"
                            disabled={p.users > 0}
                            onClick={() => {
                              setPassword("");
                              setDel(p);
                            }}
                          >
                            <IconTrash size={16} />
                          </Button>
                        </Tooltip>
                      )}
                    </Group>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={!!draft} onClose={() => setDraft(null)} title={draft?.isNew ? "Nowy profil" : `Profil „${draft?.name}”`} size="xl">
        {draft && (
          <Stack>
            <Group grow align="flex-start">
              <TextInput
                label="Nazwa"
                required
                value={draft.name}
                onChange={(e) => setDraft({ ...draft, name: e.currentTarget.value })}
                description={draft.isNew ? `identyfikator: ${draftID || "—"}` : `identyfikator: ${draft.id}`}
                error={idProblem || undefined}
              />
              <TextInput
                label="Opis"
                value={draft.description}
                onChange={(e) => setDraft({ ...draft, description: e.currentTarget.value })}
                placeholder="np. zespół SOC – pierwsza linia"
              />
            </Group>
            <Table verticalSpacing={6}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Moduł</Table.Th>
                  <Table.Th>Dostęp</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {modules.map((m) => (
                  <Table.Tr key={m.key}>
                    <Table.Td maw={300}>
                      <Text size="sm" fw={500}>
                        {m.label}
                      </Text>
                      {m.help && (
                        <Text size="xs" c="dimmed">
                          {m.help}
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <SegmentedControl
                        size="xs"
                        value={draft.permissions[m.key] ?? ""}
                        onChange={(v) => {
                          const next = { ...draft.permissions };
                          if (v) next[m.key] = v;
                          else delete next[m.key];
                          setDraft({ ...draft, permissions: next });
                        }}
                        data={[{ value: "", label: "brak" }, ...m.levels.map((l) => ({ value: l.key, label: l.label }))]}
                      />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
            {draft.permissions.users === "write" && (
              <Alert color="grape">
                Prawo zmiany w „Użytkownikach i bezpieczeństwie” czyni profil administratorem panelu: zakładanie kont, nadawanie
                profili (także sobie), wymóg MFA.
              </Alert>
            )}
            <PasswordInput label="Twoje hasło" value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
            <Group justify="flex-end">
              <Button loading={busy} disabled={!password || draft.name.trim().length < 2 || !!idProblem} onClick={() => void save()}>
                Zapisz profil
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>

      <Modal opened={!!del} onClose={() => setDel(null)} title={`Usunięcie profilu „${del?.name ?? ""}”`} centered>
        {del && (
          <Stack>
            <Text size="sm">Profil bez przypisanych kont. Zmiana trafi do audytu.</Text>
            <PasswordInput label="Twoje hasło" value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoFocus />
            <Button color="red" loading={busy} disabled={!password} onClick={() => void remove()}>
              Usuń
            </Button>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
