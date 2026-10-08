import { useCallback, useEffect, useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Group,
  Menu,
  Modal,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Textarea,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconDots, IconEdit, IconPlus, IconTrash } from "@tabler/icons-react";
import { groupsApi, type AgentGroup, type AgentLimits, type AgentProfile } from "../api";
import { useAuth } from "../auth";

export const profileLabels: Record<AgentProfile, string> = {
  workstation: "Stacja robocza",
  server: "Serwer",
  dc: "Kontroler domeny",
};

const priorityLabels: Record<string, string> = {
  normal: "normalny",
  below_normal: "poniżej normalnego",
  background: "w tle (najniższy)",
};

function msg(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

// Opis limitów w jednej linii („—” = wartość z agent.yaml / domyślna agenta).
export function limitsSummary(l: AgentLimits): string {
  const parts: string[] = [];
  if (l.cpu_max_percent !== undefined) parts.push(l.cpu_max_percent ? `CPU ≤ ${l.cpu_max_percent}%` : "CPU bez limitu");
  if (l.memory_hard_mb !== undefined) parts.push(l.memory_hard_mb ? `pamięć ≤ ${l.memory_hard_mb} MB` : "pamięć bez limitu");
  if (l.max_eps !== undefined) parts.push(l.max_eps ? `≤ ${l.max_eps} zdarzeń/s` : "zdarzenia bez limitu");
  if (l.max_send_kbps !== undefined) parts.push(l.max_send_kbps ? `łącze ≤ ${l.max_send_kbps} KiB/s` : "łącze bez limitu");
  if (l.buffer_max_mb !== undefined) parts.push(l.buffer_max_mb ? `bufor ${l.buffer_max_mb} MB` : "bez bufora dyskowego");
  if (l.priority) parts.push(`priorytet ${priorityLabels[l.priority]}`);
  return parts.length ? parts.join(" · ") : "domyślne agenta";
}

type Form = { name: string; description: string; profile: AgentProfile; limits: AgentLimits };
const emptyForm: Form = { name: "", description: "", profile: "workstation", limits: {} };

// Pole liczbowe limitu: puste = wartość domyślna agenta (pole pominięte).
function LimitInput({
  label,
  description,
  value,
  onChange,
  max,
  suffix,
}: {
  label: string;
  description: string;
  value: number | undefined;
  onChange: (v: number | undefined) => void;
  max: number;
  suffix: string;
}) {
  return (
    <NumberInput
      label={label}
      description={description}
      placeholder="domyślne agenta"
      min={0}
      max={max}
      suffix={suffix}
      value={value ?? ""}
      onChange={(v) => onChange(v === "" ? undefined : Number(v))}
    />
  );
}

export default function GroupsPage() {
  const { user } = useAuth();
  const admin = user?.role === "admin";
  const [groups, setGroups] = useState<AgentGroup[]>([]);
  const [error, setError] = useState("");
  const [edit, setEdit] = useState<{ id?: number; form: Form } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    groupsApi
      .list()
      .then((r) => setGroups(r.groups))
      .catch((e) => setError(msg(e)));
  }, []);
  useEffect(load, [load]);

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!edit) return;
    setBusy(true);
    try {
      if (edit.id) await groupsApi.update(edit.id, edit.form);
      else await groupsApi.create(edit.form);
      notifications.show({
        color: "green",
        message: "Zapisano. Agenci grupy pobiorą nową konfigurację w ciągu ok. 5 minut i zastosują ją bez restartu.",
      });
      setEdit(null);
      load();
    } catch (err) {
      notifications.show({ color: "red", message: msg(err) });
    } finally {
      setBusy(false);
    }
  };

  const remove = async (g: AgentGroup) => {
    if (!window.confirm(`Usunąć grupę „${g.name}”?`)) return;
    try {
      await groupsApi.remove(g.id);
      load();
    } catch (err) {
      notifications.show({ color: "red", message: msg(err) });
    }
  };

  const setLimit = (k: keyof AgentLimits, v: AgentLimits[keyof AgentLimits]) =>
    edit && setEdit({ ...edit, form: { ...edit.form, limits: { ...edit.form.limits, [k]: v } } });

  return (
    <Stack>
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>Grupy agentów</Title>
          <Text c="dimmed" size="sm">
            Grupa określa, jakie zdarzenia zbierają agenci (profil) i ile zasobów mogą zużyć. Agenci pobierają konfigurację
            co ok. 5 minut i stosują ją bez restartu.
          </Text>
        </div>
        {admin && (
          <Button leftSection={<IconPlus size={18} />} onClick={() => setEdit({ form: emptyForm })}>
            Nowa grupa
          </Button>
        )}
      </Group>
      {error && <Alert color="red">{error}</Alert>}

      <Table.ScrollContainer minWidth={760}>
        <Table striped verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr style={{ whiteSpace: "nowrap" }}>
              <Table.Th>Grupa</Table.Th>
              <Table.Th>Profil zdarzeń</Table.Th>
              <Table.Th>Limity</Table.Th>
              <Table.Th>Agenci</Table.Th>
              <Table.Th>Wersja</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {groups.map((g) => (
              <Table.Tr key={g.id}>
                <Table.Td>
                  <Group gap={6} wrap="nowrap">
                    <Text fw={600}>{g.name}</Text>
                    {g.is_default && (
                      <Badge size="xs" variant="light">
                        domyślna
                      </Badge>
                    )}
                  </Group>
                  {g.description && (
                    <Text size="xs" c="dimmed">
                      {g.description}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>{profileLabels[g.profile]}</Table.Td>
                <Table.Td>
                  <Text size="sm">{limitsSummary(g.limits)}</Text>
                </Table.Td>
                <Table.Td>{g.agents}</Table.Td>
                <Table.Td>
                  <Text size="xs" ff="monospace" c="dimmed">
                    {g.config_version}
                  </Text>
                </Table.Td>
                <Table.Td>
                  {admin && (
                    <Menu position="bottom-end">
                      <Menu.Target>
                        <ActionIcon variant="subtle" aria-label={`Akcje ${g.name}`}>
                          <IconDots size={18} />
                        </ActionIcon>
                      </Menu.Target>
                      <Menu.Dropdown>
                        <Menu.Item
                          leftSection={<IconEdit size={16} />}
                          onClick={() =>
                            setEdit({ id: g.id, form: { name: g.name, description: g.description, profile: g.profile, limits: g.limits } })
                          }
                        >
                          Edytuj
                        </Menu.Item>
                        {!g.is_default && (
                          <Menu.Item color="red" leftSection={<IconTrash size={16} />} onClick={() => void remove(g)}>
                            Usuń
                          </Menu.Item>
                        )}
                      </Menu.Dropdown>
                    </Menu>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={edit !== null} onClose={() => setEdit(null)} title={edit?.id ? "Edycja grupy" : "Nowa grupa"} size="lg" centered>
        {edit && (
          <form onSubmit={save}>
            <Stack>
              <TextInput
                label="Nazwa"
                required
                value={edit.form.name}
                onChange={(e) => setEdit({ ...edit, form: { ...edit.form, name: e.currentTarget.value } })}
              />
              <Textarea
                label="Opis"
                autosize
                minRows={1}
                value={edit.form.description}
                onChange={(e) => setEdit({ ...edit, form: { ...edit.form, description: e.currentTarget.value } })}
              />
              <Select
                label="Profil zdarzeń"
                description="Zestaw kanałów i Event ID (roadmapa, załącznik B)"
                data={(Object.keys(profileLabels) as AgentProfile[]).map((p) => ({ value: p, label: profileLabels[p] }))}
                value={edit.form.profile}
                allowDeselect={false}
                onChange={(v) => v && setEdit({ ...edit, form: { ...edit.form, profile: v as AgentProfile } })}
              />
              <Text fw={600} size="sm" mt="xs">
                Limity zasobów (puste pole = wartość domyślna agenta)
              </Text>
              <SimpleGrid cols={{ base: 1, sm: 2 }}>
                <LimitInput
                  label="CPU"
                  description="% całego komputera, 0 = bez limitu"
                  max={100}
                  suffix=" %"
                  value={edit.form.limits.cpu_max_percent}
                  onChange={(v) => setLimit("cpu_max_percent", v)}
                />
                <Select
                  label="Priorytet procesu"
                  description="Niższy = ustępuje programom użytkownika"
                  placeholder="domyślne agenta"
                  clearable
                  data={Object.entries(priorityLabels).map(([value, label]) => ({ value, label }))}
                  value={edit.form.limits.priority ?? null}
                  onChange={(v) => setLimit("priority", (v ?? undefined) as AgentLimits["priority"])}
                />
                <LimitInput
                  label="Pamięć – próg miękki"
                  description="MB, agent oszczędza pamięć powyżej"
                  max={8192}
                  suffix=" MB"
                  value={edit.form.limits.memory_soft_mb}
                  onChange={(v) => setLimit("memory_soft_mb", v)}
                />
                <LimitInput
                  label="Pamięć – limit twardy"
                  description="MB, Windows nie pozwoli przekroczyć"
                  max={8192}
                  suffix=" MB"
                  value={edit.form.limits.memory_hard_mb}
                  onChange={(v) => setLimit("memory_hard_mb", v)}
                />
                <LimitInput
                  label="Zdarzeń na sekundę"
                  description="0 = bez limitu"
                  max={1000000}
                  suffix=""
                  value={edit.form.limits.max_eps}
                  onChange={(v) => setLimit("max_eps", v)}
                />
                <LimitInput
                  label="Łącze"
                  description="KiB/s po kompresji, 0 = bez limitu"
                  max={10000000}
                  suffix=" KiB/s"
                  value={edit.form.limits.max_send_kbps}
                  onChange={(v) => setLimit("max_send_kbps", v)}
                />
                <LimitInput
                  label="Bufor dyskowy"
                  description="MB na paczki przy braku łączności (agent 0.6+), 0 = wyłączony; domyślnie 1024"
                  max={102400}
                  suffix=" MB"
                  value={edit.form.limits.buffer_max_mb}
                  onChange={(v) => setLimit("buffer_max_mb", v)}
                />
                <Select
                  label="Gdy bufor się zapełni"
                  description="Wstrzymanie: zdarzenia czekają w dzienniku Windows; usuwanie: tracone najstarsze paczki"
                  placeholder="domyślne agenta (wstrzymanie)"
                  clearable
                  data={[
                    { value: "pause", label: "wstrzymaj odczyt" },
                    { value: "drop_oldest", label: "usuwaj najstarsze paczki" },
                  ]}
                  value={edit.form.limits.buffer_on_full ?? null}
                  onChange={(v) => setLimit("buffer_on_full", (v ?? undefined) as AgentLimits["buffer_on_full"])}
                />
              </SimpleGrid>
              <Button type="submit" loading={busy}>
                Zapisz
              </Button>
            </Stack>
          </form>
        )}
      </Modal>
    </Stack>
  );
}
