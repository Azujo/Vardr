import { useCallback, useEffect, useRef, useState } from "react";
import {
  Alert as MAlert,
  Badge,
  Button,
  Checkbox,
  Group,
  Modal,
  SegmentedControl,
  Select,
  Stack,
  Table,
  Text,
  Textarea,
  TextInput,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAlertTriangle, IconSearch } from "@tabler/icons-react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import {
  ago,
  alertStatusLabels,
  alertsApi,
  formatDate,
  levelLabels,
  type Alert,
  type AlertLevel,
  type AlertListFilter,
  type AlertStatus,
  type RuleAttack,
} from "../api";
import { useAuth } from "../auth";
import { AttackBadges } from "../attack";
import AddToIncident from "./AddToIncident";

const engineLabels: Record<string, string> = { stream: "w locie", index_query: "zapytania", system: "wbudowana", correlation: "korelacja" };

// Gjallarhorn – lista alertów (najnowsze pierwsze) z filtrami i akcjami zbiorczymi.
export default function AlertsPage() {
  const { can } = useAuth();
  const canEdit = can("alerts", "write");
  const [params, setParams] = useSearchParams();
  const get = (k: string) => params.get(k) ?? "";
  const status = params.get("status") ?? "open";
  const filter: AlertListFilter = {
    status: status === "all" ? "" : status,
    level: get("level"),
    rule: get("rule"),
    host: get("host"),
    user: get("user"),
    assignee: get("assignee"),
    engine: get("engine"),
    q: get("q"),
    since: get("since"),
    technique: get("technique"),
    tactic: get("tactic"),
  };
  const key = JSON.stringify(filter);
  const [items, setItems] = useState<Alert[]>([]);
  const [attack, setAttack] = useState<Record<string, RuleAttack>>({});
  const [total, setTotal] = useState(0);
  const [configured, setConfigured] = useState(true);
  const [error, setError] = useState("");
  const [more, setMore] = useState(false);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [toIncident, setToIncident] = useState(false);
  const [closing, setClosing] = useState(false);
  const [reason, setReason] = useState("");
  const [search, setSearch] = useState(get("q"));
  const [assignees, setAssignees] = useState<{ value: string; label: string }[]>([]);
  const navigate = useNavigate();
  // Po doładowaniu starszych alertów automatyczne odświeżanie wstrzymane –
  // inaczej lista wracałaby do pierwszych 100 i gubiła zaznaczenia.
  const paged = useRef(false);

  useEffect(() => {
    alertsApi
      .assignees()
      .then((r) => setAssignees(r.assignees.map((a) => ({ value: a.username, label: a.display_name || a.username }))))
      .catch(() => setAssignees([]));
  }, []);

  const load = useCallback(
    (before?: number) => {
      alertsApi
        .list({ ...(JSON.parse(key) as AlertListFilter), before })
        .then((r) => {
          setConfigured(r.configured);
          paged.current = !!before;
          setItems((cur) => (before ? [...cur, ...r.alerts] : r.alerts));
          setAttack((cur) => (before ? { ...cur, ...(r.attack ?? {}) } : (r.attack ?? {})));
          setTotal(r.total);
          setMore(r.alerts.length === 100);
          setError("");
        })
        .catch((e) => setError(e instanceof Error ? e.message : String(e)));
    },
    [key],
  );
  useEffect(() => {
    load();
    setSelected(new Set());
    const t = setInterval(() => {
      if (!paged.current) load();
    }, 15000);
    return () => clearInterval(t);
  }, [load]);

  const set = (k: string, v: string) => {
    const p = new URLSearchParams(params);
    if (v) p.set(k, v);
    else p.delete(k);
    setParams(p);
  };

  const toggle = (id: number) =>
    setSelected((cur) => {
      const n = new Set(cur);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  const allSelected = items.length > 0 && items.every((a) => selected.has(a.id));

  const bulk = async (s: AlertStatus, why?: string) => {
    try {
      const r = await alertsApi.bulkStatus([...selected], s, why);
      notifications.show({ color: "green", message: `Zmieniono ${r.changed} z ${selected.size} alertów.` });
      setSelected(new Set());
      setClosing(false);
      setReason("");
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    }
  };

  const hasFilters = ["level", "rule", "host", "user", "assignee", "engine", "q", "since", "technique", "tactic"].some((k) =>
    params.get(k),
  );

  return (
    <Stack>
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>Gjallarhorn – alerty</Title>
          <Text c="dimmed" size="sm">
            Alerty z reguł detekcji. Trafienia z tym samym kluczem w oknie reguły łączą się w jeden alert z licznikiem.{" "}
            <Text span component={Link} to="/rules" c="blue" size="sm">
              Reguły →
            </Text>
          </Text>
        </div>
        <SegmentedControl
          value={status}
          onChange={(v) => set("status", v === "open" ? "" : v)}
          data={[
            { value: "open", label: "otwarte" },
            { value: "acknowledged", label: "w analizie" },
            { value: "closed", label: "zamknięte" },
            { value: "all", label: "wszystkie" },
          ]}
        />
      </Group>

      <Group gap="xs" align="flex-end" wrap="wrap">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            set("q", search.trim());
          }}
        >
          <TextInput
            w={240}
            placeholder="szukaj: reguła, opis, komputer, konto"
            leftSection={<IconSearch size={14} />}
            value={search}
            onChange={(e) => setSearch(e.currentTarget.value)}
            onBlur={() => set("q", search.trim())}
          />
        </form>
        <Select
          placeholder="każdy poziom"
          clearable
          w={150}
          value={filter.level || null}
          onChange={(v) => set("level", v ?? "")}
          data={(Object.keys(levelLabels) as AlertLevel[])
            .reverse()
            .map((l) => ({ value: l, label: `od: ${levelLabels[l].label}` }))}
        />
        <Select
          placeholder="przypisane: każde"
          clearable
          w={180}
          value={filter.assignee || null}
          onChange={(v) => set("assignee", v ?? "")}
          data={[{ value: "me", label: "moje" }, { value: "-", label: "nieprzypisane" }, ...assignees]}
        />
        <Select
          placeholder="ostatnie zdarzenie: kiedykolwiek"
          clearable
          w={220}
          value={filter.since || null}
          onChange={(v) => set("since", v ?? "")}
          data={[
            { value: "24h", label: "ostatnie 24 h" },
            { value: "7d", label: "ostatnie 7 dni" },
            { value: "30d", label: "ostatnie 30 dni" },
          ]}
        />
        <Select
          placeholder="każdy silnik"
          clearable
          w={140}
          value={filter.engine || null}
          onChange={(v) => set("engine", v ?? "")}
          data={Object.entries(engineLabels).map(([value, label]) => ({ value, label }))}
        />
        {(filter.host || filter.user || filter.rule || filter.technique || filter.tactic) && (
          <Group gap={4}>
            {filter.technique && (
              <Badge variant="outline" color="grape" style={{ cursor: "pointer" }} onClick={() => set("technique", "")}>
                ATT&CK {filter.technique} ✕
              </Badge>
            )}
            {filter.tactic && (
              <Badge variant="outline" color="grape" style={{ cursor: "pointer" }} onClick={() => set("tactic", "")}>
                taktyka {filter.tactic} ✕
              </Badge>
            )}
            {filter.host && (
              <Badge variant="outline" style={{ cursor: "pointer" }} onClick={() => set("host", "")}>
                komputer: {filter.host} ✕
              </Badge>
            )}
            {filter.user && (
              <Badge variant="outline" style={{ cursor: "pointer" }} onClick={() => set("user", "")}>
                konto: {filter.user} ✕
              </Badge>
            )}
            {filter.rule && (
              <Badge variant="outline" style={{ cursor: "pointer" }} onClick={() => set("rule", "")}>
                reguła ✕
              </Badge>
            )}
          </Group>
        )}
        {hasFilters && (
          <Button
            variant="subtle"
            size="xs"
            onClick={() => {
              setSearch("");
              setParams(status === "open" ? {} : { status });
            }}
          >
            wyczyść filtry
          </Button>
        )}
      </Group>

      {error && <MAlert color="red">{error}</MAlert>}
      {!configured && (
        <MAlert color="gray" icon={<IconAlertTriangle />}>
          Detektor (siem-detector) jeszcze nie działał – nie ma alertów ani reguł.
        </MAlert>
      )}

      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          {total} {total === 1 ? "alert" : "alertów"} w tym widoku
          {items.length < total ? ` (pokazane ${items.length})` : ""}
        </Text>
        {canEdit && selected.size > 0 && (
          <Group gap="xs">
            <Text size="sm">zaznaczone: {selected.size}</Text>
            <Button size="xs" onClick={() => void bulk("acknowledged")}>
              Weź do analizy
            </Button>
            <Button size="xs" color="gray" variant="light" onClick={() => setClosing(true)}>
              Zamknij
            </Button>
            <Button size="xs" variant="subtle" onClick={() => void bulk("open")}>
              Otwórz ponownie
            </Button>
            {can("incidents", "write") && (
              <Button size="xs" variant="light" color="red" onClick={() => setToIncident(true)}>
                Do incydentu
              </Button>
            )}
          </Group>
        )}
      </Group>

      {configured && items.length === 0 && (
        <Text c="dimmed" size="sm">
          Brak alertów w tym widoku.
        </Text>
      )}
      {items.length > 0 && (
        <Table.ScrollContainer minWidth={1000}>
          <Table striped highlightOnHover verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr style={{ whiteSpace: "nowrap" }}>
                {canEdit && (
                  <Table.Th w={36}>
                    <Checkbox
                      aria-label="zaznacz wszystkie"
                      checked={allSelected}
                      indeterminate={selected.size > 0 && !allSelected}
                      onChange={() => setSelected(allSelected ? new Set() : new Set(items.map((a) => a.id)))}
                    />
                  </Table.Th>
                )}
                <Table.Th>Poziom</Table.Th>
                <Table.Th>Reguła</Table.Th>
                <Table.Th>Komputer</Table.Th>
                <Table.Th>Konto</Table.Th>
                <Table.Th>Trafienia</Table.Th>
                <Table.Th>Ostatnie zdarzenie</Table.Th>
                <Table.Th>Stan</Table.Th>
                <Table.Th>Przypisany</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((a) => (
                <Table.Tr key={a.id} style={{ cursor: "pointer" }} onClick={() => navigate(`/alerts/${a.id}`)}>
                  {canEdit && (
                    <Table.Td onClick={(e) => e.stopPropagation()}>
                      <Checkbox aria-label={`zaznacz alert ${a.id}`} checked={selected.has(a.id)} onChange={() => toggle(a.id)} />
                    </Table.Td>
                  )}
                  <Table.Td>
                    <Badge color={levelLabels[a.level].color}>{levelLabels[a.level].label}</Badge>
                  </Table.Td>
                  <Table.Td maw={420}>
                    <Text size="sm" fw={500}>
                      {a.rule_title}
                    </Text>
                    <Text size="xs" c="dimmed" lineClamp={1} title={a.summary}>
                      {a.summary}
                    </Text>
                    <AttackBadges ra={attack[a.rule_id]} tactics={false} size="xs" />
                  </Table.Td>
                  <Table.Td onClick={(e) => e.stopPropagation()}>
                    {a.host_name ? (
                      <Text size="sm" c="blue" style={{ cursor: "pointer" }} onClick={() => set("host", a.host_name)} title="pokaż alerty z tego komputera">
                        {a.host_name}
                      </Text>
                    ) : (
                      "—"
                    )}
                  </Table.Td>
                  <Table.Td onClick={(e) => e.stopPropagation()}>
                    {a.user_name ? (
                      <Text size="sm" c="blue" style={{ cursor: "pointer" }} onClick={() => set("user", a.user_name)} title="pokaż alerty tego konta">
                        {a.user_name}
                      </Text>
                    ) : (
                      "—"
                    )}
                  </Table.Td>
                  <Table.Td>{a.hits}</Table.Td>
                  <Table.Td style={{ whiteSpace: "nowrap" }} title={formatDate(a.last_seen)}>
                    {ago(a.last_seen)}
                  </Table.Td>
                  <Table.Td>
                    <Badge variant="light" color={alertStatusLabels[a.status].color}>
                      {alertStatusLabels[a.status].label}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" c={a.assignee ? undefined : "dimmed"}>
                      {a.assignee || "—"}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      {more && (
        <Group>
          <Button variant="subtle" onClick={() => load(items[items.length - 1].id)}>
            Starsze alerty
          </Button>
        </Group>
      )}

      <AddToIncident
        alertIds={[...selected]}
        defaultTitle={items.find((a) => selected.has(a.id))?.rule_title}
        opened={toIncident}
        onClose={() => setToIncident(false)}
      />
      <Modal opened={closing} onClose={() => setClosing(false)} title={`Zamknij zaznaczone alerty (${selected.size})`} centered>
        <Stack>
          <Textarea
            label="Powód"
            description="trafi do każdego alertu i do audytu, np. fałszywy alarm – skaner podatności"
            autosize
            minRows={2}
            value={reason}
            onChange={(e) => setReason(e.currentTarget.value)}
          />
          <Button disabled={reason.trim().length < 3} onClick={() => void bulk("closed", reason)}>
            Zamknij
          </Button>
        </Stack>
      </Modal>
    </Stack>
  );
}
