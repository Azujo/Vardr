// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Card,
  Code,
  CopyButton,
  Drawer,
  Group,
  Loader,
  Popover,
  ScrollArea,
  SegmentedControl,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { IconCheck, IconCopy, IconFilter, IconHelp, IconLink, IconRefresh, IconSearch } from "@tabler/icons-react";
import { Link, useSearchParams } from "react-router-dom";
import { eventsApi, formatNumber, type EventDetail, type EventRow } from "../api";
import { useAuth } from "../auth";
import { maxPicks, togglePick, usePicks } from "../corrPicks";

const ranges: Record<string, { label: string; ms: number }> = {
  "15m": { label: "15 min", ms: 15 * 60e3 },
  "1h": { label: "1 h", ms: 3600e3 },
  "24h": { label: "24 h", ms: 24 * 3600e3 },
  "7d": { label: "7 dni", ms: 7 * 24 * 3600e3 },
};

const outcomeColor: Record<string, string> = { success: "green", failure: "red" };

function msg(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

function fmtTime(iso: string) {
  const d = new Date(iso);
  return d.toLocaleString("pl-PL", { dateStyle: "short", timeStyle: "medium" });
}

// Wartość z odstępami wymaga cudzysłowu w zapytaniu.
function filterFor(field: string, value: string): string {
  return /[\s"]/.test(value) ? `${field}:"${value.replace(/"/g, "")}"` : `${field}:${value}`;
}

// Proste formatowanie XML zdarzenia (wcięcia) do podglądu.
function prettyXml(xml: string): string {
  const parts = xml.replace(/>\s*</g, ">\n<").split("\n");
  let depth = 0;
  return parts
    .map((line) => {
      if (/^<\//.test(line)) depth = Math.max(0, depth - 1);
      const out = "  ".repeat(depth) + line;
      if (/^<[^!?/][^>]*[^/]>$/.test(line) && !/<\/[^>]+>$/.test(line)) depth++;
      return out;
    })
    .join("\n");
}

function Histogram({
  buckets,
  intervalS,
  onPick,
}: {
  buckets: { t: string; count: number }[];
  intervalS: number;
  onPick: (from: Date, to: Date) => void;
}) {
  const max = Math.max(1, ...buckets.map((b) => b.count));
  const w = 1000;
  const h = 90;
  const bw = buckets.length ? w / buckets.length : w;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} preserveAspectRatio="none" role="img" aria-label="Histogram zdarzeń">
      {buckets.map((b, i) => {
        const bh = Math.max(1, (b.count / max) * (h - 4));
        const from = new Date(b.t);
        return (
          <rect
            key={b.t}
            x={i * bw + 1}
            y={h - bh}
            width={Math.max(1, bw - 2)}
            height={bh}
            fill="var(--mantine-color-indigo-5)"
            style={{ cursor: "pointer" }}
            onClick={() => onPick(from, new Date(from.getTime() + intervalS * 1000))}
          >
            <title>{`${fmtTime(b.t)}: ${b.count.toLocaleString("pl-PL")} zdarzeń (kliknij, aby zawęzić)`}</title>
          </rect>
        );
      })}
    </svg>
  );
}

function SyntaxHelp({ fields }: { fields: { name: string; help: string }[] }) {
  return (
    <Popover width={460} position="bottom-end" withArrow shadow="md">
      <Popover.Target>
        <ActionIcon variant="default" size="lg" aria-label="Składnia zapytań">
          <IconHelp size={18} />
        </ActionIcon>
      </Popover.Target>
      <Popover.Dropdown>
        <Stack gap={6}>
          <Text fw={600} size="sm">
            Składnia zapytań
          </Text>
          <Text size="xs">
            <Code>user:jkowalski code:4625</Code> – pole:wartość (wiele warunków = wszystkie naraz)
            <br />
            <Code>host:pc0*</Code> – prefiks · <Code>-action:logged-out</Code> – negacja
            <br />
            <Code>"invoke-expression" powershell</Code> – tekst w treści zdarzenia
            <br />
            <Code>fields.TargetUserName:admin</Code> – dowolne pole źródłowe zdarzenia
          </Text>
          <Table fz="xs" verticalSpacing={2}>
            <Table.Tbody>
              {fields.map((f) => (
                <Table.Tr key={f.name}>
                  <Table.Td>
                    <Code>{f.name}</Code>
                  </Table.Td>
                  <Table.Td>{f.help}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Stack>
      </Popover.Dropdown>
    </Popover>
  );
}

function EventDrawer({
  row,
  source,
  onClose,
  onFilter,
}: {
  row: EventRow | null;
  source?: string;
  onClose: () => void;
  onFilter: (f: string) => void;
}) {
  const [ev, setEv] = useState<EventDetail | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    setEv(null);
    setError("");
    if (!row) return;
    eventsApi
      .get(row.event_id, row.timestamp, source)
      .then((r) => setEv(r.event))
      .catch((e) => setError(msg(e)));
  }, [row, source]);
  const xml = useMemo(() => (ev?.raw ? prettyXml(ev.raw) : ""), [ev]);
  const { can } = useAuth();
  const picks = usePicks();
  const canWizard = can("rules", "test") && source !== "replay";
  const picked = ev ? picks.some((p) => p.id === ev.event_id) : false;
  const fieldEntries = Object.entries(ev?.fields ?? {}).sort(([a], [b]) => a.localeCompare(b));

  return (
    <Drawer opened={row !== null} onClose={onClose} position="right" size="xl" title={row ? `Zdarzenie ${row.code} – ${row.host}` : ""}>
      {error && <Alert color="red">{error}</Alert>}
      {!ev && !error && <Loader />}
      {ev && (
        <Stack>
          {canWizard && (
            <Group gap="xs">
              <Button
                size="xs"
                variant={picked ? "filled" : "light"}
                leftSection={<IconLink size={14} />}
                disabled={!picked && picks.length >= maxPicks}
                onClick={() =>
                  togglePick({
                    id: ev.event_id,
                    ts: ev.timestamp,
                    label: `${ev.code || ev.action || ev.dataset} · ${ev.host}${ev.user ? ` · ${ev.user}` : ""}`,
                  })
                }
              >
                {picked ? "Usuń z kreatora korelacji" : "Dodaj do kreatora korelacji"}
              </Button>
              {picks.length > 0 && (
                <Button size="xs" variant="subtle" component={Link} to="/rules/correlation">
                  Otwórz kreator ({picks.length})
                </Button>
              )}
            </Group>
          )}
          <SimpleGrid cols={2} spacing="xs">
            {[
              ["Czas zdarzenia", fmtTime(ev.timestamp)],
              ["Przyjęte", fmtTime(ev.ingested)],
              ["Host", ev.host],
              ["Agent", ev.agent_id],
              ["Źródło", ev.dataset],
              ["Dostawca", ev.provider],
              ["Akcja", ev.action || "—"],
              ["Wynik", ev.outcome || "—"],
              ["Użytkownik", ev.user ? (ev.domain ? `${ev.domain}\\${ev.user}` : ev.user) : "—"],
              ["Osoba", ev.identity || "—"],
              ["Adres IP", ev.ip || "—"],
              ["Proces", ev.process || "—"],
              ["Identyfikator", ev.event_id],
            ].map(([k, v]) => (
              <div key={k}>
                <Text size="xs" c="dimmed">
                  {k}
                </Text>
                <Text size="sm" style={{ wordBreak: "break-all" }}>
                  {v}
                </Text>
              </div>
            ))}
          </SimpleGrid>
          {ev.command_line && (
            <div>
              <Text size="xs" c="dimmed">
                Linia poleceń
              </Text>
              <Code block style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                {ev.command_line}
              </Code>
            </div>
          )}
          {ev.message && (
            <div>
              <Text size="xs" c="dimmed">
                Opis
              </Text>
              <Text size="sm">{ev.message}</Text>
            </div>
          )}
          {(ev.time_quality || ev.truncated) && (
            <Group gap="xs">
              {ev.time_quality && <Badge color="orange">czas: {ev.time_quality}</Badge>}
              {ev.truncated && <Badge color="orange">zdarzenie przycięte przez agenta</Badge>}
            </Group>
          )}

          <Title order={5}>Pola zdarzenia</Title>
          <Table fz="sm" verticalSpacing={4} striped>
            <Table.Tbody>
              {fieldEntries.map(([k, v]) => (
                <Table.Tr key={k}>
                  <Table.Td style={{ whiteSpace: "nowrap", verticalAlign: "top" }}>
                    <Code>{k}</Code>
                  </Table.Td>
                  <Table.Td style={{ wordBreak: "break-all" }}>{v}</Table.Td>
                  <Table.Td w={36}>
                    {v && v.length < 200 && (
                      <Tooltip label="Filtruj po tej wartości">
                        <ActionIcon variant="subtle" size="sm" onClick={() => onFilter(filterFor(`fields.${k}`, v))}>
                          <IconFilter size={14} />
                        </ActionIcon>
                      </Tooltip>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>

          <Group justify="space-between">
            <Title order={5}>Surowe zdarzenie (XML)</Title>
            {ev.raw && (
              <CopyButton value={ev.raw}>
                {({ copied, copy }) => (
                  <Button size="xs" variant="default" leftSection={copied ? <IconCheck size={14} /> : <IconCopy size={14} />} onClick={copy}>
                    {copied ? "Skopiowano" : "Kopiuj"}
                  </Button>
                )}
              </CopyButton>
            )}
          </Group>
          {ev.raw ? (
            <ScrollArea.Autosize mah={420}>
              <Code block>{xml}</Code>
            </ScrollArea.Autosize>
          ) : (
            <Text size="sm" c="dimmed">
              Oryginał usunięty przez retencję surowego XML (zostały pola znormalizowane).
            </Text>
          )}
        </Stack>
      )}
    </Drawer>
  );
}

export default function EventsPage() {
  const [params, setParams] = useSearchParams();
  const q = params.get("q") ?? "";
  const range = params.get("range") ?? (params.get("from") ? "custom" : "1h");
  const source = params.get("source") === "replay" ? "replay" : undefined;
  const [input, setInput] = useState(q);
  const [rows, setRows] = useState<EventRow[]>([]);
  const [next, setNext] = useState<{ before_ts: string; before_id: string } | undefined>();
  const [hist, setHist] = useState<{ buckets: { t: string; count: number }[]; interval_s: number; total: number } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [took, setTook] = useState(0);
  const [selected, setSelected] = useState<EventRow | null>(null);
  const [fields, setFields] = useState<{ name: string; help: string }[]>([]);
  const [reload, setReload] = useState(0);
  const picks = usePicks();

  useEffect(() => {
    eventsApi
      .fields()
      .then((r) => setFields(r.fields))
      .catch(() => {});
  }, []);
  useEffect(() => setInput(q), [q]);

  // Zakres czasu: z adresu (zawężenie z histogramu) albo względem „teraz”.
  const span = useMemo(() => {
    if (range === "custom" && params.get("from") && params.get("to")) {
      return { from: params.get("from")!, to: params.get("to")! };
    }
    const now = Date.now();
    return { from: new Date(now - (ranges[range] ?? ranges["1h"]).ms).toISOString(), to: new Date(now).toISOString() };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [range, params, reload]);

  useEffect(() => {
    setLoading(true);
    setError("");
    const p = { q, from: span.from.replace(/\.\d+Z$/, "Z"), to: span.to.replace(/\.\d+Z$/, "Z"), source };
    Promise.all([eventsApi.search(p), eventsApi.histogram(p)])
      .then(([s, h]) => {
        setRows(s.events);
        setNext(s.next);
        setTook(s.took_ms);
        setHist(h);
      })
      .catch((e) => {
        setRows([]);
        setHist(null);
        setError(msg(e));
      })
      .finally(() => setLoading(false));
  }, [q, span, source]);

  const search = (text: string) => {
    const p = new URLSearchParams(params);
    if (text.trim()) p.set("q", text.trim());
    else p.delete("q");
    setParams(p);
  };
  const addFilter = (f: string) => {
    setSelected(null);
    search(q.includes(f) ? q : `${q} ${f}`.trim());
  };
  const setRange = (r: string) => {
    const p = new URLSearchParams(params);
    p.set("range", r);
    p.delete("from");
    p.delete("to");
    setParams(p);
  };
  const zoom = (from: Date, to: Date) => {
    const p = new URLSearchParams(params);
    p.set("range", "custom");
    p.set("from", from.toISOString().replace(/\.\d+Z$/, "Z"));
    p.set("to", to.toISOString().replace(/\.\d+Z$/, "Z"));
    setParams(p);
  };
  const more = useCallback(() => {
    if (!next) return;
    eventsApi
      .search({ q, from: span.from.replace(/\.\d+Z$/, "Z"), to: span.to.replace(/\.\d+Z$/, "Z"), ...next })
      .then((s) => {
        setRows((r) => [...r, ...s.events]);
        setNext(s.next);
      })
      .catch((e) => setError(msg(e)));
  }, [next, q, span]);

  const cell = (field: string, value: string | number, label?: string) =>
    value === "" || value === 0 ? (
      <Text size="sm" c="dimmed">
        —
      </Text>
    ) : (
      <Text
        size="sm"
        style={{ cursor: "pointer" }}
        title="Kliknij, aby filtrować"
        onClick={(e) => {
          e.stopPropagation();
          addFilter(filterFor(field, String(value)));
        }}
      >
        {label ?? value}
      </Text>
    );

  return (
    <Stack>
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>Mímir – zdarzenia</Title>
          <Text c="dimmed" size="sm">
            Wyszukiwanie zdarzeń zebranych przez agentów. Kliknięcie wartości w tabeli dodaje filtr.
          </Text>
        </div>
        {picks.length > 0 && (
          <Button variant="light" leftSection={<IconLink size={16} />} component={Link} to="/rules/correlation">
            Kreator korelacji ({picks.length})
          </Button>
        )}
      </Group>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          search(input);
        }}
      >
        <Group wrap="nowrap" gap="xs">
          <TextInput
            style={{ flex: 1 }}
            placeholder='np. code:4625 user:jkowalski albo "invoke-expression"'
            leftSection={<IconSearch size={16} />}
            value={input}
            onChange={(e) => setInput(e.currentTarget.value)}
            styles={{ input: { fontFamily: "var(--mantine-font-family-monospace)" } }}
          />
          <Button type="submit">Szukaj</Button>
          <SyntaxHelp fields={fields} />
        </Group>
      </form>

      <Group justify="space-between" wrap="wrap">
        <Group gap="xs">
          <SegmentedControl
            size="xs"
            value={range === "custom" ? "" : range}
            onChange={setRange}
            data={Object.entries(ranges).map(([value, r]) => ({ value, label: r.label }))}
          />
          {range === "custom" && (
            <Badge variant="light" size="lg">
              {fmtTime(span.from)} – {fmtTime(span.to)}
            </Badge>
          )}
          <Tooltip label="Zdarzenia odtworzone z archiwum NIS2 są w osobnej tabeli – nie mieszają się z bieżącymi">
            <SegmentedControl
              size="xs"
              color={source ? "orange" : undefined}
              value={source ?? "live"}
              onChange={(v) => {
                const p = new URLSearchParams(params);
                if (v === "replay") p.set("source", "replay");
                else p.delete("source");
                setParams(p);
              }}
              data={[
                { value: "live", label: "Bieżące" },
                { value: "replay", label: "Odtworzone z archiwum" },
              ]}
            />
          </Tooltip>
          <Tooltip label="Odśwież">
            <ActionIcon variant="default" onClick={() => setReload((r) => r + 1)} aria-label="Odśwież">
              <IconRefresh size={16} />
            </ActionIcon>
          </Tooltip>
        </Group>
        <Text size="sm" c="dimmed">
          {loading ? "szukam…" : hist ? `${formatNumber(hist.total)} zdarzeń · ${took} ms` : ""}
        </Text>
      </Group>

      {error && <Alert color="red">{error}</Alert>}

      {hist && hist.buckets.length > 0 && (
        <Card withBorder padding="xs">
          <Histogram buckets={hist.buckets} intervalS={hist.interval_s} onPick={zoom} />
        </Card>
      )}

      <Table.ScrollContainer minWidth={980}>
        <Table highlightOnHover verticalSpacing={6} fz="sm">
          <Table.Thead>
            <Table.Tr style={{ whiteSpace: "nowrap" }}>
              <Table.Th>Czas</Table.Th>
              <Table.Th>Host</Table.Th>
              <Table.Th>Zdarzenie</Table.Th>
              <Table.Th>Akcja</Table.Th>
              <Table.Th>Użytkownik</Table.Th>
              <Table.Th>Adres IP</Table.Th>
              <Table.Th>Szczegóły</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.map((r) => (
              <Table.Tr key={r.event_id} style={{ cursor: "pointer" }} onClick={() => setSelected(r)}>
                <Table.Td style={{ whiteSpace: "nowrap" }}>{fmtTime(r.timestamp)}</Table.Td>
                <Table.Td style={{ whiteSpace: "nowrap" }}>{cell("host", r.host)}</Table.Td>
                <Table.Td style={{ whiteSpace: "nowrap" }}>
                  <Group gap={4} wrap="nowrap">
                    {cell("code", r.code)}
                    <Text size="xs" c="dimmed">
                      {r.dataset.replace("windows.", "")}
                    </Text>
                  </Group>
                </Table.Td>
                <Table.Td>
                  {r.action ? (
                    <Badge
                      variant="light"
                      color={outcomeColor[r.outcome] ?? "gray"}
                      style={{ cursor: "pointer" }}
                      onClick={(e) => {
                        e.stopPropagation();
                        addFilter(filterFor("action", r.action));
                      }}
                    >
                      {r.action}
                    </Badge>
                  ) : (
                    <Text size="sm" c="dimmed">
                      —
                    </Text>
                  )}
                </Table.Td>
                <Table.Td style={{ whiteSpace: "nowrap" }}>
                  {cell("user", r.user)}
                  {r.identity && r.identity !== r.user.toLowerCase() && (
                    <Text size="xs" c="dimmed">
                      osoba: {cell("identity", r.identity)}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td style={{ whiteSpace: "nowrap" }}>{cell("ip", r.ip)}</Table.Td>
                <Table.Td maw={380}>
                  <Text size="sm" lineClamp={1} c="dimmed">
                    {r.process || r.message}
                  </Text>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      {!loading && rows.length === 0 && !error && (
        <Text c="dimmed" size="sm">
          Brak zdarzeń w tym zakresie. Spróbuj dłuższego zakresu czasu albo innego zapytania.
        </Text>
      )}
      {next && (
        <Group>
          <Button variant="default" onClick={more}>
            Załaduj starsze
          </Button>
        </Group>
      )}

      <EventDrawer row={selected} source={source} onClose={() => setSelected(null)} onFilter={addFilter} />
    </Stack>
  );
}
