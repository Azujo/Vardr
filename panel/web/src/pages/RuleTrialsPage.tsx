// SPDX-License-Identifier: AGPL-3.0-or-later

// Próby reguł: reguły w trybie próbnym liczą trafienia bez alertów – tu widać
// wynik (trafienia, dni, komputery, ostatnie zdarzenie) i rekomendację, czy
// regułę można włączyć, a administrator włącza albo wyłącza je zbiorczo.
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert as MAlert,
  Anchor,
  Badge,
  Button,
  Checkbox,
  Code,
  Group,
  SegmentedControl,
  Stack,
  Table,
  Text,
  Title,
  Tooltip,
} from "@mantine/core";
import { IconArrowLeft } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { alertsApi, formatDate, levelLabels, rulesApi, type BulkRuleAction, type RuleInfo, type TrialStat } from "../api";
import { useAuth } from "../auth";
import RuleBulkModal, { bulkLabels } from "./RuleBulkModal";

type Verdict = "short" | "quiet" | "rare" | "moderate" | "noisy";

// Rekomendacja: po co najmniej dobie – cicha (0 trafień), rzadka (< 1/dzień),
// umiarkowana (< 20/dzień) albo głośna.
const verdicts: Record<Verdict, { label: string; color: string; help: string }> = {
  short: { label: "za krótko", color: "gray", help: "próba trwa krócej niż dobę – poczekaj na wynik" },
  quiet: { label: "cicha – można włączyć", color: "green", help: "brak trafień – reguła nie hałasuje na tych danych" },
  rare: { label: "rzadka", color: "teal", help: "mniej niż 1 trafienie dziennie – przejrzyj przykłady i włącz" },
  moderate: { label: "umiarkowana", color: "yellow", help: "1–20 trafień dziennie – sprawdź, czy to prawdziwe zdarzenia, rozważ wyjątki" },
  noisy: { label: "głośna", color: "red", help: "ponad 20 trafień dziennie – bez dostrojenia zaleje alertami" },
};

function verdictOf(t: TrialStat, now: number): { v: Verdict; days: number; perDay: number } {
  const days = (now - new Date(t.since).getTime()) / 86400000;
  const perDay = t.hits / Math.max(days, 1);
  if (days < 1) return { v: "short", days, perDay };
  if (t.hits === 0) return { v: "quiet", days, perDay };
  if (perDay < 1) return { v: "rare", days, perDay };
  if (perDay < 20) return { v: "moderate", days, perDay };
  return { v: "noisy", days, perDay };
}

// Zdarzenia z okolicy ostatniego trafienia w Mímirze (komputer, ±2 min).
function aroundLink(t: TrialStat): string {
  if (!t.last_at) return "";
  const at = new Date(t.last_at).getTime();
  const host = t.top_hosts.length === 1 ? t.top_hosts[0].host : "";
  const p = new URLSearchParams({
    range: "custom",
    from: new Date(at - 120000).toISOString(),
    to: new Date(at + 120000).toISOString(),
  });
  if (host && host !== "(inne)") p.set("q", `host:${host}`);
  return `/events?${p.toString()}`;
}

export default function RuleTrialsPage() {
  const { can } = useAuth();
  const admin = can("rules", "write");
  const [trials, setTrials] = useState<TrialStat[]>([]);
  const [rules, setRules] = useState<Record<string, RuleInfo>>({});
  const [now, setNow] = useState(Date.now());
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("all");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulk, setBulk] = useState<BulkRuleAction | null>(null);

  const load = useCallback(() => {
    Promise.all([rulesApi.trials(), alertsApi.rules()])
      .then(([t, r]) => {
        setTrials(t.trials);
        setNow(new Date(t.now).getTime());
        setRules(Object.fromEntries(r.rules.map((x) => [x.id, x])));
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);
  useEffect(() => load(), [load]);

  const rows = useMemo(
    () =>
      trials
        .map((t) => ({ t, r: rules[t.rule_id], ...verdictOf(t, now) }))
        .filter((x) => filter === "all" || x.v === filter)
        .sort((a, b) => b.perDay - a.perDay || b.t.hits - a.t.hits),
    [trials, rules, now, filter],
  );
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const t of trials) {
      const v = verdictOf(t, now).v;
      c[v] = (c[v] ?? 0) + 1;
    }
    return c;
  }, [trials, now]);
  const allSel = rows.length > 0 && rows.every((x) => selected.has(x.t.rule_id));

  return (
    <Stack>
      <Anchor component={Link} to="/rules" size="sm">
        <Group gap={4}>
          <IconArrowLeft size={14} /> reguły detekcji
        </Group>
      </Anchor>
      <div>
        <Title order={2}>Próby reguł</Title>
        <Text c="dimmed" size="sm" maw={860}>
          Reguła w trybie próbnym jest oceniana na bieżących zdarzeniach (silnik w locie), ale nie tworzy alertów ani
          powiadomień – liczy tylko trafienia od początku próby. Tryb próbny ustawisz na stronie reguł (pojedynczo albo dla
          zaznaczonych, np. wszystkich reguł SigmaHQ wysokiego poziomu). Reguły progowe liczą trafienia warunku, bez progu.
        </Text>
      </div>
      {error && <MAlert color="red">{error}</MAlert>}
      {trials.length === 0 && !error && (
        <MAlert color="gray">
          Żadna reguła nie jest w trybie próbnym. Na stronie <Anchor component={Link} to="/rules">reguł</Anchor> zaznacz reguły
          (np. filtr SigmaHQ, poziom wysoki i krytyczny) i wybierz „Tryb próbny”.
        </MAlert>
      )}
      {trials.length > 0 && (
        <Group gap="xs">
          <SegmentedControl
            value={filter}
            onChange={setFilter}
            data={[
              { value: "all", label: `Wszystkie (${trials.length})` },
              ...(["noisy", "moderate", "rare", "quiet", "short"] as Verdict[]).map((v) => ({
                value: v,
                label: `${verdicts[v].label.split(" –")[0]} (${counts[v] ?? 0})`,
              })),
            ]}
          />
        </Group>
      )}
      {admin && selected.size > 0 && (
        <Group gap="xs">
          <Text size="sm" fw={500}>
            Zaznaczone: {selected.size}
          </Text>
          {(["enable", "disable", "file"] as BulkRuleAction[]).map((a) => (
            <Button key={a} size="xs" variant="light" color={a === "disable" ? "red" : undefined} onClick={() => setBulk(a)}>
              {a === "enable" ? "Włącz (z alertami)" : a === "disable" ? "Wyłącz (koniec próby)" : bulkLabels[a]}
            </Button>
          ))}
          <Button size="xs" variant="subtle" onClick={() => setSelected(new Set())}>
            wyczyść zaznaczenie
          </Button>
        </Group>
      )}
      {rows.length > 0 && (
        <Table.ScrollContainer minWidth={1000}>
          <Table striped verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                {admin && (
                  <Table.Th w={36}>
                    <Checkbox
                      size="xs"
                      checked={allSel}
                      onChange={(e) => {
                        const on = e.currentTarget.checked;
                        setSelected((s) => {
                          const n = new Set(s);
                          for (const x of rows) {
                            if (on) n.add(x.t.rule_id);
                            else n.delete(x.t.rule_id);
                          }
                          return n;
                        });
                      }}
                      aria-label="zaznacz wszystkie"
                    />
                  </Table.Th>
                )}
                <Table.Th>Ocena</Table.Th>
                <Table.Th>Reguła</Table.Th>
                <Table.Th>Próba</Table.Th>
                <Table.Th>Trafienia</Table.Th>
                <Table.Th>Komputery</Table.Th>
                <Table.Th>Ostatnie trafienie</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {rows.map(({ t, r, v, days, perDay }) => (
                <Table.Tr key={t.rule_id}>
                  {admin && (
                    <Table.Td>
                      <Checkbox
                        size="xs"
                        checked={selected.has(t.rule_id)}
                        onChange={(e) => {
                          const on = e.currentTarget.checked;
                          setSelected((s) => {
                            const n = new Set(s);
                            if (on) n.add(t.rule_id);
                            else n.delete(t.rule_id);
                            return n;
                          });
                        }}
                        aria-label="zaznacz regułę"
                      />
                    </Table.Td>
                  )}
                  <Table.Td>
                    <Tooltip label={verdicts[v].help} multiline w={260}>
                      <Badge color={verdicts[v].color} variant="light">
                        {verdicts[v].label}
                      </Badge>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td maw={380}>
                    <Group gap={6} wrap="nowrap">
                      {r && <Badge size="xs" color={levelLabels[r.level].color}>{levelLabels[r.level].label}</Badge>}
                      <Text size="sm" fw={500} lineClamp={1}>
                        {r?.title ?? t.rule_id}
                      </Text>
                    </Group>
                    <Text size="xs" c="dimmed" ff="monospace" lineClamp={1}>
                      {r?.file ?? "(reguły nie ma już w katalogu)"}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="xs">od {formatDate(t.since)}</Text>
                    <Text size="xs" c="dimmed">
                      {days < 1 ? `${Math.max(0, Math.round(days * 24))} h` : `${days.toFixed(1)} dni`} · {t.changed_by}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" fw={500}>
                      {t.hits}
                    </Text>
                    <Text size="xs" c="dimmed">
                      {perDay < 10 ? perDay.toFixed(1) : Math.round(perDay)}/dzień
                    </Text>
                  </Table.Td>
                  <Table.Td maw={220}>
                    <Text size="xs">{t.hosts}</Text>
                    <Text size="xs" c="dimmed" lineClamp={2}>
                      {t.top_hosts.map((h) => `${h.host || "(brak)"} ${h.hits}`).join(", ")}
                    </Text>
                  </Table.Td>
                  <Table.Td maw={340}>
                    {t.last_at ? (
                      <>
                        <Anchor component={Link} to={aroundLink(t)} size="xs">
                          {formatDate(t.last_at)}
                        </Anchor>
                        <Text size="xs" c="dimmed" lineClamp={2}>
                          {t.sample_summary}
                        </Text>
                      </>
                    ) : (
                      <Text size="xs" c="dimmed">
                        –
                      </Text>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      <Text size="xs" c="dimmed">
        Próby działają w silniku w locie (<Code>SIEM_DETECTION_MODE</Code> stream albo both). Trafienia są przechowywane 35 dni;
        ponowne rozpoczęcie próby liczy od zera.
      </Text>
      <RuleBulkModal
        ids={[...selected]}
        action={bulk}
        onClose={() => setBulk(null)}
        onDone={() => {
          setBulk(null);
          setSelected(new Set());
          load();
        }}
      />
    </Stack>
  );
}
