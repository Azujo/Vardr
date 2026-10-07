import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Group,
  List,
  Modal,
  MultiSelect,
  NumberInput,
  PasswordInput,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  TagsInput,
  Text,
  Textarea,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAlertTriangle, IconLock, IconSettings } from "@tabler/icons-react";
import {
  agentsApi,
  ApiError,
  archiveApi,
  formatDate,
  formatDuration,
  groupsApi,
  policyStatusLabels,
  unarchivedReasonLabels,
  weakeningLabels,
  type AgentGroup,
  type AgentView,
  type ArchivePolicy as Policy,
  type PolicyChange,
  type PolicyInfo,
  type Weakening,
} from "../api";

// Te same reguły co w serwerze (urd.Weakening) – tylko do podpowiedzi
// w formularzu; rozstrzyga serwer.
function weakening(cur: Policy, next: { enabled: boolean; retention_days: number; excluded_groups: number[]; excluded_agents: string[] }) {
  const w: Weakening[] = [];
  if (cur.enabled && !next.enabled) w.push("disable");
  if (next.retention_days < cur.retention_days) w.push("retention");
  if (next.excluded_groups.some((g) => !cur.excluded_groups.includes(g))) w.push("groups");
  if (next.excluded_agents.some((a) => !cur.excluded_agents.includes(a))) w.push("agents");
  return w;
}

function until(iso?: string) {
  if (!iso) return "";
  const s = Math.max(0, Math.round((new Date(iso).getTime() - Date.now()) / 1000));
  return s === 0 ? "za chwilę" : `za ${formatDuration(s)}`;
}

function sources(c: { excluded_groups: number[]; excluded_agents: string[] }, groupName: (id: number) => string) {
  const parts = [...c.excluded_groups.map(groupName), ...c.excluded_agents];
  return parts.length ? parts.join(", ") : "—";
}

// Polityka archiwum: włączenie, retencja i źródła objęte archiwum. Zmianę
// rozpatruje archiwizator – wzmocnienie od razu, osłabienie po karencji
// i tylko po ponownym podaniu hasła.
export default function ArchivePolicy({ admin, onChanged }: { admin: boolean; onChanged: () => void }) {
  const [info, setInfo] = useState<PolicyInfo | null>(null);
  const [groups, setGroups] = useState<AgentGroup[]>([]);
  const [agents, setAgents] = useState<AgentView[]>([]);
  const [error, setError] = useState("");

  const [enabled, setEnabled] = useState(true);
  const [days, setDays] = useState<number | string>(30);
  const [exGroups, setExGroups] = useState<string[]>([]);
  const [exAgents, setExAgents] = useState<string[]>([]);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState<Weakening[] | null>(null);
  const [password, setPassword] = useState("");

  const reset = useCallback((p: Policy | null) => {
    if (!p) return;
    setEnabled(p.enabled);
    setDays(p.retention_days);
    setExGroups(p.excluded_groups.map(String));
    setExAgents(p.excluded_agents);
  }, []);

  const load = useCallback(
    (resetForm: boolean) => {
      archiveApi
        .policy()
        .then((r) => {
          setInfo(r);
          setError("");
          if (resetForm) reset(r.policy);
        })
        .catch((e) => setError(e instanceof Error ? e.message : String(e)));
    },
    [reset],
  );
  useEffect(() => {
    load(true);
    groupsApi
      .list()
      .then((r) => setGroups(r.groups))
      .catch(() => {});
    agentsApi
      .list()
      .then((r) => setAgents(r.agents))
      .catch(() => {});
    const t = setInterval(() => load(false), 15000);
    return () => clearInterval(t);
  }, [load]);

  const groupName = useCallback(
    (id: number) => groups.find((g) => g.id === id)?.name ?? `grupa #${id} (usunięta)`,
    [groups],
  );
  const target = useMemo(
    () => ({
      enabled,
      retention_days: Number(days) || 0,
      excluded_groups: exGroups.map(Number),
      excluded_agents: exAgents,
    }),
    [enabled, days, exGroups, exAgents],
  );
  const pol = info?.policy ?? null;
  const b = info?.bounds;
  const weak = pol ? weakening(pol, target) : [];
  const dirty =
    !!pol &&
    (pol.enabled !== target.enabled ||
      pol.retention_days !== target.retention_days ||
      [...pol.excluded_groups].sort().join() !== [...target.excluded_groups].sort().join() ||
      [...pol.excluded_agents].sort().join() !== [...target.excluded_agents].sort().join());

  const send = async (pw?: string) => {
    setBusy(true);
    try {
      const r = await archiveApi.changePolicy({ ...target, reason, password: pw });
      notifications.show({ color: r.weakening.length ? "orange" : "green", message: r.message, autoClose: 8000 });
      setConfirm(null);
      setPassword("");
      setReason("");
      load(false);
      onChanged();
    } catch (e) {
      if (e instanceof ApiError && e.code === "reauth_required") {
        setConfirm(weak.length ? weak : ["disable"]);
      } else {
        notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
      }
    } finally {
      setBusy(false);
    }
  };

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (weak.length) setConfirm(weak);
    else void send();
  };

  const cancel = async (c: PolicyChange) => {
    try {
      const r = await archiveApi.cancelChange(c.id);
      notifications.show({ color: "green", message: r.message });
      load(false);
      onChanged();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    }
  };

  if (error) return <Alert color="red">{error}</Alert>;
  if (!info) return null;
  if (!pol)
    return (
      <Alert color="gray">Polityka nie jest jeszcze zapisana – archiwizator zakłada ją przy pierwszym starcie.</Alert>
    );

  const sc = info.scheduled_change;
  const groupOptions = groups.map((g) => ({ value: String(g.id), label: `${g.name} (${g.agents} agentów)` }));
  for (const id of pol.excluded_groups)
    if (!groups.some((g) => g.id === id)) groupOptions.push({ value: String(id), label: groupName(id) });

  return (
    <Stack>
      {sc && (
        <Alert color="orange" icon={<IconAlertTriangle />} title={`Zaplanowane osłabienie polityki – wejdzie w życie ${until(sc.effective_at)}`}>
          <Text size="sm">
            {sc.requested_by} zlecił(a) {formatDate(sc.requested_at)}: {sc.weakening.map((w) => weakeningLabels[w]).join(", ")}.
            Powód: „{sc.reason}”. Termin: {formatDate(sc.effective_at)}.
          </Text>
          <Text size="sm" mt={4}>
            Docelowo: archiwizacja {sc.enabled ? "włączona" : "WYŁĄCZONA"}, retencja {sc.retention_days} dni, wyłączone źródła:{" "}
            {sources(sc, groupName)}.
          </Text>
          {admin && (
            <Button mt="sm" size="xs" color="orange" variant="light" onClick={() => void cancel(sc)}>
              Anuluj tę zmianę
            </Button>
          )}
        </Alert>
      )}

      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Card withBorder>
          <Stack gap={6}>
            <Title order={4}>Obowiązująca polityka</Title>
            <Group gap="xs">
              <Text size="sm">Archiwizacja nowych paczek:</Text>
              <Badge color={pol.enabled ? "green" : "red"} variant="light">
                {pol.enabled ? "włączona" : "wyłączona"}
              </Badge>
            </Group>
            <Text size="sm">
              Retencja: <b>{pol.retention_days} dni</b>
            </Text>
            <Text size="sm">Wyłączone grupy: {pol.excluded_groups.length ? pol.excluded_groups.map(groupName).join(", ") : "—"}</Text>
            <Text size="sm">Wyłączeni agenci: {pol.excluded_agents.length ? pol.excluded_agents.join(", ") : "—"}</Text>
            <Text size="xs" c="dimmed">
              Ostatnia zmiana: {pol.updated_by}, {formatDate(pol.updated_at)}
            </Text>
          </Stack>
        </Card>
        <Card withBorder>
          <Stack gap={6}>
            <Title order={4}>Granice z konfiguracji serwera</Title>
            <Text size="sm">
              Retencja: od <b>{b?.min_retention_days} dni</b> do <b>{b?.max_retention_days} dni</b>
            </Text>
            <Text size="sm">
              Karencja osłabień: <b>{b?.grace_s ? formatDuration(b.grace_s) : "brak"}</b>
            </Text>
            <Text size="sm">
              Zawsze pomijane (prefiksy agentów): {b?.exclude_prefixes.length ? b.exclude_prefixes.join(", ") : "—"}
            </Text>
            <Text size="xs" c="dimmed">
              Ustawiane w konfiguracji archiwizatora (SIEM_ARCHIVE_MIN/MAX_RETENTION_DAYS, SIEM_ARCHIVE_POLICY_GRACE,
              SIEM_ARCHIVE_EXCLUDE_AGENTS) – panel ich nie zmieni.
            </Text>
          </Stack>
        </Card>
      </SimpleGrid>

      {admin && (
        <Card withBorder>
          <form onSubmit={submit}>
            <Stack gap="sm">
              <Group gap="xs">
                <IconSettings size={20} />
                <Title order={4}>Zmień politykę</Title>
              </Group>
              <Text size="sm" c="dimmed">
                Włączenie archiwum, dłuższa retencja albo objęcie archiwum kolejnych źródeł działają w ciągu minuty. Wyłączenie,
                krótsza retencja albo wyłączenie źródeł osłabiają ochronę: wymagają ponownego podania hasła, wchodzą w życie po
                karencji ({b?.grace_s ? formatDuration(b.grace_s) : "brak"}) i do tego czasu można je anulować. Wyłączenie
                dotyczy tylko nowych paczek – zarchiwizowane dane zostają do końca retencji. Każda zmiana trafia do audytu.
              </Text>
              <Switch
                label="Archiwizuj nowe paczki logów"
                checked={enabled}
                onChange={(e) => setEnabled(e.currentTarget.checked)}
              />
              <NumberInput
                label="Retencja (dni)"
                description={`od ${b?.min_retention_days} do ${b?.max_retention_days} dni`}
                min={b?.min_retention_days}
                max={b?.max_retention_days}
                value={days}
                onChange={setDays}
                maw={240}
                required
              />
              <MultiSelect
                label="Grupy agentów wyłączone z archiwum"
                description="agent przeniesiony do wyłączonej grupy (także tokenem rejestracyjnym) wypada z archiwum dopiero po karencji"
                data={groupOptions}
                value={exGroups}
                onChange={setExGroups}
                searchable
                clearable
              />
              <TagsInput
                label="Agenci wyłączeni z archiwum"
                description="identyfikatory agentów (podpowiedzi z listy agentów; Enter dodaje)"
                data={agents.map((a) => ({ value: a.id, label: `${a.id} (${a.hostname})` }))}
                value={exAgents}
                onChange={setExAgents}
                clearable
              />
              <Textarea
                label="Powód zmiany"
                description="trafi do audytu i historii polityki"
                required
                minLength={5}
                maxLength={1000}
                autosize
                minRows={2}
                value={reason}
                onChange={(e) => setReason(e.currentTarget.value)}
              />
              {weak.length > 0 && dirty && (
                <Alert color="orange" variant="light" icon={<IconLock />}>
                  Ta zmiana osłabia ochronę ({weak.map((w) => weakeningLabels[w]).join(", ")}) – po zatwierdzeniu poprosimy o hasło.
                </Alert>
              )}
              <Group>
                <Button type="submit" loading={busy} disabled={!dirty} color={weak.length ? "orange" : undefined}>
                  Zleć zmianę
                </Button>
                <Button variant="subtle" onClick={() => reset(pol)} disabled={!dirty}>
                  Przywróć obowiązujące
                </Button>
              </Group>
            </Stack>
          </form>
        </Card>
      )}

      <Card withBorder>
        <Stack gap="xs">
          <Title order={4}>
            Źródła bez archiwizacji ({info.unarchived.length} z {info.agents_total ?? 0} agentów)
          </Title>
          {info.unarchived.length === 0 ? (
            <Text size="sm" c="dimmed">
              Wszyscy zarejestrowani agenci są archiwizowani.
            </Text>
          ) : (
            <Table.ScrollContainer minWidth={600}>
              <Table striped verticalSpacing={4}>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Agent</Table.Th>
                    <Table.Th>Komputer</Table.Th>
                    <Table.Th>Grupa</Table.Th>
                    <Table.Th>Powód</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {info.unarchived.slice(0, 200).map((u) => (
                    <Table.Tr key={u.agent_id}>
                      <Table.Td>{u.agent_id}</Table.Td>
                      <Table.Td>{u.hostname}</Table.Td>
                      <Table.Td>{u.group}</Table.Td>
                      <Table.Td>
                        {unarchivedReasonLabels[u.reason]}
                        {u.effective_at && ` – od ${formatDate(u.effective_at)}`}
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )}
          {info.unarchived.length > 200 && (
            <Text size="xs" c="dimmed">
              Pokazano 200 pierwszych.
            </Text>
          )}
        </Stack>
      </Card>

      {info.changes.length > 0 && (
        <Stack gap="xs">
          <Title order={4}>Historia zmian polityki</Title>
          <Table.ScrollContainer minWidth={900}>
            <Table striped verticalSpacing="xs">
              <Table.Thead>
                <Table.Tr style={{ whiteSpace: "nowrap" }}>
                  <Table.Th>Nr</Table.Th>
                  <Table.Th>Zlecono</Table.Th>
                  <Table.Th>Kto / powód</Table.Th>
                  <Table.Th>Docelowa polityka</Table.Th>
                  <Table.Th>Osłabienie</Table.Th>
                  <Table.Th>Stan</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {info.changes.map((c) => (
                  <Table.Tr key={c.id}>
                    <Table.Td>{c.id}</Table.Td>
                    <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(c.requested_at)}</Table.Td>
                    <Table.Td maw={260}>
                      <Group gap={4}>
                        <Text size="sm">{c.requested_by}</Text>
                        {c.reauth && (
                          <Tooltip label="potwierdzone hasłem">
                            <IconLock size={14} />
                          </Tooltip>
                        )}
                      </Group>
                      <Text size="xs" c="dimmed" lineClamp={2} title={c.reason}>
                        {c.reason}
                      </Text>
                    </Table.Td>
                    <Table.Td maw={300}>
                      <Text size="sm">
                        {c.enabled ? "włączone" : "WYŁĄCZONE"}, {c.retention_days} dni
                      </Text>
                      <Text size="xs" c="dimmed" lineClamp={2}>
                        bez: {sources(c, groupName)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      {c.weakening.length ? (
                        <Text size="sm" c="orange">
                          {c.weakening.map((w) => weakeningLabels[w]).join(", ")}
                        </Text>
                      ) : (
                        <Text size="sm" c="dimmed">
                          —
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Tooltip
                        label={
                          c.error ||
                          (c.status === "scheduled"
                            ? `wejdzie w życie ${formatDate(c.effective_at)}`
                            : c.status === "cancelled"
                              ? `anulował(a) ${c.cancelled_by}, ${formatDate(c.cancelled_at)}`
                              : c.applied_at
                                ? `w życie od ${formatDate(c.applied_at)}`
                                : "archiwizator rozpatrzy zlecenie w ciągu minuty")
                        }
                        multiline
                        maw={400}
                      >
                        <Badge color={policyStatusLabels[c.status].color} variant="light">
                          {c.cancelled_at && (c.status === "pending" || c.status === "scheduled")
                            ? "anulowanie…"
                            : policyStatusLabels[c.status].label}
                        </Badge>
                      </Tooltip>
                    </Table.Td>
                    <Table.Td>
                      {admin && (c.status === "pending" || c.status === "scheduled") && !c.cancelled_at && (
                        <Button size="compact-xs" variant="subtle" color="gray" onClick={() => void cancel(c)}>
                          anuluj
                        </Button>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Stack>
      )}

      <Modal opened={!!confirm} onClose={() => setConfirm(null)} title="Potwierdź osłabienie ochrony archiwum" centered>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void send(password);
          }}
        >
          <Stack gap="sm">
            <Text size="sm">Zmiana obejmuje:</Text>
            <List size="sm">
              {(confirm ?? []).map((w) => (
                <List.Item key={w}>{weakeningLabels[w]}</List.Item>
              ))}
            </List>
            <Text size="sm">
              Wejdzie w życie po karencji ({b?.grace_s ? formatDuration(b.grace_s) : "od razu"}); do tego czasu panel i alert
              pokazują ją jako zaplanowaną i można ją anulować.
            </Text>
            <PasswordInput
              label="Twoje hasło"
              required
              autoFocus
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
            />
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setConfirm(null)}>
                Wróć
              </Button>
              <Button type="submit" color="orange" loading={busy}>
                Potwierdź i zleć
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Stack>
  );
}
