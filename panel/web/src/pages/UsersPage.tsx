// SPDX-License-Identifier: AGPL-3.0-or-later

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
  PasswordInput,
  SegmentedControl,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  IconCheck,
  IconCopy,
  IconDots,
  IconKey,
  IconLock,
  IconLockOpen,
  IconShieldOff,
  IconUserPlus,
} from "@tabler/icons-react";
import { api, formatDate, roleLabels, type MFAPolicy, type Profile, type Role, type User } from "../api";
import { useAuth } from "../auth";


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
  const { user: me, can } = useAuth();
  const canWrite = can("users", "write");
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const roleOptions = profiles.length
    ? profiles.map((p) => ({ value: p.id, label: p.name }))
    : Object.entries(roleLabels).map(([value, label]) => ({ value, label }));
  const isAdminProfile = (id: string) => profiles.find((p) => p.id === id)?.admin ?? id === "admin";
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [temp, setTemp] = useState<{ user: User; temp_password: string } | null>(null);
  const [form, setForm] = useState({ username: "", display_name: "", role: "viewer" as Role });
  const [busy, setBusy] = useState(false);
  const [mfa, setMfa] = useState<Record<string, string>>({});
  const [mfaAvailable, setMfaAvailable] = useState(false);
  const [policy, setPolicy] = useState<MFAPolicy>("all");
  const [policyEdit, setPolicyEdit] = useState<MFAPolicy | null>(null);
  const [mfaReset, setMfaReset] = useState<User | null>(null);
  const [password, setPassword] = useState("");

  const load = useCallback(() => {
    api
      .users()
      .then((r) => {
        setUsers(r.users);
        setMfa(r.mfa ?? {});
        setMfaAvailable(!!r.mfa_available);
        if (r.mfa_policy) setPolicy(r.mfa_policy);
      })
      .catch((e) => setError(errorMessage(e)));
    api
      .profiles()
      .then((r) => setProfiles(r.profiles))
      .catch(() => setProfiles([]));
  }, []);
  const savePolicy = async () => {
    if (!policyEdit) return;
    setBusy(true);
    try {
      await api.setSecuritySettings(policyEdit, password);
      notifications.show({ color: "green", message: "Zapisano wymaganie drugiego składnika" });
      setPolicyEdit(null);
      setPassword("");
      load();
    } catch (err) {
      notifications.show({ color: "red", message: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };
  const resetMFA = async () => {
    if (!mfaReset) return;
    setBusy(true);
    try {
      await api.resetUserMFA(mfaReset.id, password);
      notifications.show({ color: "green", message: `Drugi składnik konta ${mfaReset.username} usunięty` });
      setMfaReset(null);
      setPassword("");
      load();
    } catch (err) {
      notifications.show({ color: "red", message: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  };
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
            Konta panelu i ich profile uprawnień (Administracja → Profile uprawnień). Każda zmiana trafia do dziennika audytu.
          </Text>
        </div>
        {canWrite && (
          <Button leftSection={<IconUserPlus size={18} />} onClick={() => setCreateOpen(true)}>
            Nowe konto
          </Button>
        )}
      </Group>
      {error && <Alert color="red">{error}</Alert>}
      {mfaAvailable ? (
        <Group gap="sm" align="center">
          <Text size="sm" fw={500}>
            Drugi składnik logowania (TOTP) wymagany od:
          </Text>
          <SegmentedControl
            size="xs"
            disabled={!canWrite}
            value={policy}
            onChange={(v) => {
              if (v !== policy) {
                setPassword("");
                setPolicyEdit(v as MFAPolicy);
              }
            }}
            data={[
              { value: "all", label: "wszystkich" },
              { value: "admins", label: "administratorów" },
              { value: "none", label: "nikogo (dobrowolnie)" },
            ]}
          />
        </Group>
      ) : (
        <Alert color="gray">
          Drugi składnik logowania niedostępny – brak klucza MFA na serwerze (plik <Code>certs/mfa.key</Code>, tworzy go{" "}
          <Code>deploy.sh config</Code>).
        </Alert>
      )}

      <Table.ScrollContainer minWidth={720}>
        <Table striped highlightOnHover verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Login</Table.Th>
              <Table.Th>Nazwa</Table.Th>
              <Table.Th>Profil</Table.Th>
              <Table.Th>Stan</Table.Th>
              <Table.Th>MFA</Table.Th>
              <Table.Th>Ostatnie logowanie</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {users.map((u) => (
              <Table.Tr key={u.id}>
                <Table.Td>
                  <Group gap={6}>
                    <Text fw={500}>{u.username}</Text>
                    {u.source === "ldap" && (
                      <Tooltip label="konto domenowe – hasło i profil z Active Directory">
                        <Badge size="xs" color="cyan" variant="light">
                          AD
                        </Badge>
                      </Tooltip>
                    )}
                  </Group>
                </Table.Td>
                <Table.Td>{u.display_name || "—"}</Table.Td>
                <Table.Td>
                  <Select
                    size="xs"
                    w={180}
                    data={roleOptions}
                    value={u.role}
                    allowDeselect={false}
                    disabled={!canWrite || u.source === "ldap"}
                    title={u.source === "ldap" ? "profil konta domenowego wynika z grup AD" : undefined}
                    aria-label={`Profil ${u.username}`}
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
                  {mfa[String(u.id)] ? (
                    <Tooltip label={`włączone ${formatDate(mfa[String(u.id)])}`}>
                      <Badge color="green" variant="light">
                        TOTP
                      </Badge>
                    </Tooltip>
                  ) : (
                    <Badge color={policy === "all" || (policy === "admins" && isAdminProfile(u.role)) ? "orange" : "gray"} variant="light">
                      {policy === "all" || (policy === "admins" && isAdminProfile(u.role)) ? "skonfiguruje przy logowaniu" : "brak"}
                    </Badge>
                  )}
                </Table.Td>
                <Table.Td>
                  <Text size="sm">{formatDate(u.last_login_at)}</Text>
                </Table.Td>
                <Table.Td>
                  {canWrite && (
                  <Menu position="bottom-end">
                    <Menu.Target>
                      <ActionIcon variant="subtle" aria-label={`Akcje ${u.username}`}>
                        <IconDots size={18} />
                      </ActionIcon>
                    </Menu.Target>
                    <Menu.Dropdown>
                      {u.source !== "ldap" && (
                        <Menu.Item leftSection={<IconKey size={16} />} onClick={() => void reset(u)}>
                          Nowe hasło startowe
                        </Menu.Item>
                      )}
                      {mfa[String(u.id)] && (
                        <Menu.Item
                          leftSection={<IconShieldOff size={16} />}
                          onClick={() => {
                            setPassword("");
                            setMfaReset(u);
                          }}
                        >
                          Resetuj drugi składnik
                        </Menu.Item>
                      )}
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
                  )}
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
              label="Profil uprawnień"
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
      <Modal opened={!!policyEdit} onClose={() => setPolicyEdit(null)} title="Wymaganie drugiego składnika" centered>
        {policyEdit && (
          <Stack>
            <Text size="sm">
              {policyEdit === "none"
                ? "Drugi składnik będzie dobrowolny – do zalogowania wystarczy samo hasło."
                : `Konta ${policyEdit === "all" ? "" : "administratorów "}bez drugiego składnika skonfigurują go przy najbliższym logowaniu; ich bieżące sesje bez drugiego składnika zostaną zakończone.`}
            </Text>
            <PasswordInput label="Twoje hasło" value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoFocus />
            <Button color={policyEdit === "none" ? "red" : undefined} loading={busy} disabled={!password} onClick={() => void savePolicy()}>
              Zapisz
            </Button>
          </Stack>
        )}
      </Modal>
      <Modal opened={!!mfaReset} onClose={() => setMfaReset(null)} title={`Reset drugiego składnika – ${mfaReset?.username ?? ""}`} centered>
        {mfaReset && (
          <Stack>
            <Text size="sm">
              Np. przy zgubionym telefonie. Konto straci aplikację i kody zapasowe, jego sesje zostaną zakończone; przy
              następnym logowaniu skonfiguruje aplikację od nowa (jeśli drugi składnik jest wymagany). Zmiana trafi do audytu.
            </Text>
            <PasswordInput label="Twoje hasło" value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoFocus />
            <Button color="red" loading={busy} disabled={!password} onClick={() => void resetMFA()}>
              Resetuj
            </Button>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
