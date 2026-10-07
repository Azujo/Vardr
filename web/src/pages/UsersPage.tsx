import { useCallback, useEffect, useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Code,
  CopyButton,
  Group,
  Menu,
  Modal,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCheck, IconCopy, IconDots, IconKey, IconLock, IconLockOpen, IconUserPlus } from "@tabler/icons-react";
import { api, formatDate, roleLabels, type Role, type User } from "../api";
import { useAuth } from "../auth";

const roleOptions = (Object.keys(roleLabels) as Role[]).map((r) => ({ value: r, label: roleLabels[r] }));

function errorMessage(err: unknown) {
  return err instanceof Error ? err.message : String(err);
}

// Hasło startowe pokazywane jeden raz – administrator przekazuje je użytkownikowi.
function TempPassword({ data, onClose }: { data: { user: User; temp_password: string } | null; onClose: () => void }) {
  return (
    <Modal opened={data !== null} onClose={onClose} title="Hasło startowe" centered>
      {data && (
        <Stack>
          <Text size="sm">
            Konto <b>{data.user.username}</b>. Przekaż hasło użytkownikowi bezpiecznym kanałem – przy pierwszym
            logowaniu ustawi własne. <b>Hasło nie zostanie pokazane ponownie.</b>
          </Text>
          <Group>
            <Code fz="lg" style={{ flex: 1 }}>
              {data.temp_password}
            </Code>
            <CopyButton value={data.temp_password}>
              {({ copied, copy }) => (
                <Button leftSection={copied ? <IconCheck size={16} /> : <IconCopy size={16} />} onClick={copy}>
                  {copied ? "Skopiowano" : "Kopiuj"}
                </Button>
              )}
            </CopyButton>
          </Group>
          <Button variant="default" onClick={onClose}>
            Gotowe
          </Button>
        </Stack>
      )}
    </Modal>
  );
}

export default function UsersPage() {
  const { user: me } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [temp, setTemp] = useState<{ user: User; temp_password: string } | null>(null);
  const [form, setForm] = useState({ username: "", display_name: "", role: "viewer" as Role });
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api
      .users()
      .then((r) => setUsers(r.users))
      .catch((e) => setError(errorMessage(e)));
  }, []);
  useEffect(load, [load]);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await api.createUser(form);
      setCreateOpen(false);
      setForm({ username: "", display_name: "", role: "viewer" });
      setTemp(res);
      load();
    } catch (err) {
      notifications.show({ color: "red", message: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };

  const update = async (u: User, patch: { role?: Role; disabled?: boolean }) => {
    try {
      await api.updateUser(u.id, patch);
      notifications.show({ color: "green", message: `Zapisano zmiany konta ${u.username}` });
      load();
    } catch (err) {
      notifications.show({ color: "red", message: errorMessage(err) });
    }
  };

  const reset = async (u: User) => {
    if (!window.confirm(`Nadać nowe hasło startowe dla ${u.username}? Bieżące sesje tego konta zostaną zakończone.`)) return;
    try {
      setTemp(await api.resetPassword(u.id));
      load();
    } catch (err) {
      notifications.show({ color: "red", message: errorMessage(err) });
    }
  };

  const locked = (u: User) => u.locked_until && new Date(u.locked_until) > new Date();

  return (
    <Stack>
      <Group justify="space-between">
        <div>
          <Title order={2}>Użytkownicy</Title>
          <Text c="dimmed" size="sm">
            Konta panelu i ich role. Każda zmiana trafia do dziennika audytu.
          </Text>
        </div>
        <Button leftSection={<IconUserPlus size={18} />} onClick={() => setCreateOpen(true)}>
          Nowe konto
        </Button>
      </Group>
      {error && <Alert color="red">{error}</Alert>}

      <Table.ScrollContainer minWidth={720}>
        <Table striped highlightOnHover verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Login</Table.Th>
              <Table.Th>Nazwa</Table.Th>
              <Table.Th>Rola</Table.Th>
              <Table.Th>Stan</Table.Th>
              <Table.Th>Ostatnie logowanie</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {users.map((u) => (
              <Table.Tr key={u.id}>
                <Table.Td>
                  <Text fw={500}>{u.username}</Text>
                </Table.Td>
                <Table.Td>{u.display_name || "—"}</Table.Td>
                <Table.Td>
                  <Select
                    size="xs"
                    w={150}
                    data={roleOptions}
                    value={u.role}
                    allowDeselect={false}
                    aria-label={`Rola ${u.username}`}
                    onChange={(v) => v && v !== u.role && void update(u, { role: v as Role })}
                  />
                </Table.Td>
                <Table.Td>
                  <Group gap={4}>
                    {u.disabled ? (
                      <Badge color="gray">wyłączone</Badge>
                    ) : (
                      <Badge color="green" variant="light">
                        aktywne
                      </Badge>
                    )}
                    {u.must_change_password && (
                      <Badge color="yellow" variant="light">
                        hasło startowe
                      </Badge>
                    )}
                    {locked(u) && (
                      <Tooltip label={`do ${formatDate(u.locked_until)}`}>
                        <Badge color="orange" variant="light">
                          zablokowane
                        </Badge>
                      </Tooltip>
                    )}
                  </Group>
                </Table.Td>
                <Table.Td>
                  <Text size="sm">{formatDate(u.last_login_at)}</Text>
                </Table.Td>
                <Table.Td>
                  <Menu position="bottom-end">
                    <Menu.Target>
                      <ActionIcon variant="subtle" aria-label={`Akcje ${u.username}`}>
                        <IconDots size={18} />
                      </ActionIcon>
                    </Menu.Target>
                    <Menu.Dropdown>
                      <Menu.Item leftSection={<IconKey size={16} />} onClick={() => void reset(u)}>
                        Nowe hasło startowe
                      </Menu.Item>
                      {u.id !== me?.id &&
                        (u.disabled ? (
                          <Menu.Item leftSection={<IconLockOpen size={16} />} onClick={() => void update(u, { disabled: false })}>
                            Włącz konto
                          </Menu.Item>
                        ) : (
                          <Menu.Item
                            color="red"
                            leftSection={<IconLock size={16} />}
                            onClick={() => void update(u, { disabled: true })}
                          >
                            Wyłącz konto
                          </Menu.Item>
                        ))}
                    </Menu.Dropdown>
                  </Menu>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={createOpen} onClose={() => setCreateOpen(false)} title="Nowe konto" centered>
        <form onSubmit={create}>
          <Stack>
            <TextInput
              label="Login"
              description="2–64 znaki: litery, cyfry, kropka, myślnik, podkreślenie"
              required
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.currentTarget.value })}
            />
            <TextInput
              label="Nazwa wyświetlana"
              value={form.display_name}
              onChange={(e) => setForm({ ...form, display_name: e.currentTarget.value })}
            />
            <Select
              label="Rola"
              data={roleOptions}
              value={form.role}
              allowDeselect={false}
              onChange={(v) => v && setForm({ ...form, role: v as Role })}
            />
            <Button type="submit" loading={busy}>
              Utwórz i pokaż hasło startowe
            </Button>
          </Stack>
        </form>
      </Modal>
      <TempPassword data={temp} onClose={() => setTemp(null)} />
    </Stack>
  );
}
