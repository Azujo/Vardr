import { useCallback, useEffect, useState } from "react";
import {
  Alert as MAlert,
  Anchor,
  Badge,
  Button,
  Code,
  Group,
  Select,
  Stack,
  Table,
  Tabs,
  TagsInput,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconLink, IconTrash } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { formatDate, formatNumber, identitiesApi, type IdentityAlias, type Person } from "../api";
import { useAuth } from "../auth";

function err(e: unknown) {
  notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
}

function eventsLink(identity: string) {
  const v = /[\s"]/.test(identity) ? `"${identity.replace(/"/g, "")}"` : identity;
  return `/events?q=${encodeURIComponent(`identity:${v}`)}`;
}

export default function IdentitiesPage() {
  const { user } = useAuth();
  const admin = user?.role === "admin";
  const [tab, setTab] = useState<string | null>("people");
  const [domains, setDomains] = useState<string[]>([]);
  const [savedDomains, setSavedDomains] = useState<string[]>([]);
  const [aliases, setAliases] = useState<IdentityAlias[]>([]);
  const [delivery, setDelivery] = useState(true);
  const [people, setPeople] = useState<Person[]>([]);
  const [suggestions, setSuggestions] = useState<{ identities: string[] }[]>([]);
  const [hours, setHours] = useState("168");
  const [q, setQ] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [alias, setAlias] = useState("");
  const [target, setTarget] = useState("");
  const [note, setNote] = useState("");
  const [testUser, setTestUser] = useState("");
  const [testDomain, setTestDomain] = useState("");
  const [testResult, setTestResult] = useState<string | null>(null);
  const [seen, setSeen] = useState<{ domain: string; events: number; covered: boolean }[]>([]);

  const loadConfig = useCallback(() => {
    identitiesApi
      .get()
      .then((r) => {
        setDomains(r.domains);
        setSavedDomains(r.domains);
        setAliases(r.aliases);
        setDelivery(r.delivery);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);
  const loadPeople = useCallback(() => {
    identitiesApi
      .people(Number(hours), q.trim())
      .then((r) => {
        setPeople(r.people);
        setSuggestions(r.suggestions);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [hours, q]);
  useEffect(() => loadConfig(), [loadConfig]);
  useEffect(() => {
    identitiesApi
      .domainsSeen()
      .then((r) => setSeen(r.domains))
      .catch(() => setSeen([]));
  }, [savedDomains]);
  const uncovered = seen.filter((d) => !d.covered);
  useEffect(() => loadPeople(), [loadPeople]);

  const saveDomains = async () => {
    setBusy(true);
    try {
      const r = await identitiesApi.setDomains(domains);
      notifications.show({ color: "green", message: r.message });
      loadConfig();
    } catch (e) {
      err(e);
    } finally {
      setBusy(false);
    }
  };
  const addAlias = async (a: string, id: string, n: string) => {
    setBusy(true);
    try {
      const r = await identitiesApi.setAlias(a, id, n);
      notifications.show({ color: "green", message: r.message });
      setAlias("");
      setTarget("");
      setNote("");
      loadConfig();
    } catch (e) {
      err(e);
    } finally {
      setBusy(false);
    }
  };
  const removeAlias = async (a: string) => {
    try {
      const r = await identitiesApi.deleteAlias(a);
      notifications.show({ color: "green", message: r.message });
      loadConfig();
    } catch (e) {
      err(e);
    }
  };
  const test = async () => {
    try {
      setTestResult((await identitiesApi.resolve(testUser, testDomain)).identity);
    } catch (e) {
      err(e);
    }
  };
  const domainsChanged = domains.join(",") !== savedDomains.join(",");

  return (
    <Stack>
      <div>
        <Title order={2}>Tożsamości</Title>
        <Text c="dimmed" size="sm" maw={900}>
          Każde zdarzenie z kontem dostaje <b>osobę</b> (<Code>user.identity</Code>): nazwę konta bez domeny, małymi literami – to samo konto
          w AD (<Code>AZUJO\jkowalski</Code>), w Entra ID (<Code>jkowalski@azujo.pl</Code>) i na VPN (<Code>jkowalski</Code>) to jedna osoba.
          Dzięki temu reguły i wyszukiwarka łączą zdarzenia z różnych źródeł. Konta techniczne (komputery, usługi systemowe) osoby nie mają.
          Zmiany działają dla nowych zdarzeń w ciągu kilku sekund; zapisanych nie zmieniają.
        </Text>
      </div>
      {error && <MAlert color="red">{error}</MAlert>}
      {uncovered.length > 0 && (
        <MAlert color="orange" title="Domeny kont spoza listy domen organizacji">
          W zdarzeniach z ostatnich 7 dni są konta z domen spoza listy: {uncovered.map((d) => `${d.domain} (${formatNumber(d.events)})`).join(", ")}.
          Ich osoby dostają nazwę z domeną (np. <Code>azujo\jan</Code>) i nie łączą się z tą samą osobą z innych źródeł. Jeśli to domeny
          organizacji – dodaj je w zakładce „Domeny organizacji” (konta lokalne komputerów zostaw poza listą).
        </MAlert>
      )}
      {!delivery && (
        <MAlert color="orange">Panel nie jest połączony z NATS – zmiany trafią do normalizatorów po przywróceniu połączenia.</MAlert>
      )}
      <Tabs value={tab} onChange={setTab}>
        <Tabs.List>
          <Tabs.Tab value="people">Osoby</Tabs.Tab>
          <Tabs.Tab value="suggestions">
            Podpowiedzi {suggestions.length > 0 && <Badge size="xs">{suggestions.length}</Badge>}
          </Tabs.Tab>
          <Tabs.Tab value="aliases">Aliasy kont ({aliases.length})</Tabs.Tab>
          <Tabs.Tab value="domains">Domeny organizacji</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="people" pt="sm">
          <Stack gap="xs">
            <Group align="flex-end" gap="xs">
              <Select
                label="Okres"
                w={160}
                allowDeselect={false}
                value={hours}
                onChange={(v) => setHours(v ?? "168")}
                data={[
                  { value: "24", label: "ostatnie 24 h" },
                  { value: "168", label: "ostatnie 7 dni" },
                  { value: "720", label: "ostatnie 30 dni" },
                ]}
              />
              <TextInput label="Szukaj" placeholder="osoba albo konto" w={240} value={q} onChange={(e) => setQ(e.currentTarget.value)} />
            </Group>
            <Text size="xs" c="dimmed">
              Najaktywniejsze osoby (do 500) – z jakich źródeł i kont. Kliknij osobę, aby zobaczyć jej zdarzenia w Mímirze.
            </Text>
            <Table.ScrollContainer minWidth={900}>
              <Table striped verticalSpacing="xs">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Osoba</Table.Th>
                    <Table.Th>Źródła</Table.Th>
                    <Table.Th>Konta</Table.Th>
                    <Table.Th>Zdarzenia</Table.Th>
                    <Table.Th>Nieudane</Table.Th>
                    <Table.Th>Komputery</Table.Th>
                    <Table.Th>Ostatnio</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {people.map((p) => (
                    <Table.Tr key={p.identity}>
                      <Table.Td>
                        <Anchor component={Link} to={eventsLink(p.identity)} size="sm" fw={500}>
                          {p.identity}
                        </Anchor>
                      </Table.Td>
                      <Table.Td>
                        <Group gap={4}>
                          {p.datasets.map((d) => (
                            <Badge key={d} size="xs" variant="light" tt="none">
                              {d}
                            </Badge>
                          ))}
                        </Group>
                      </Table.Td>
                      <Table.Td maw={320}>
                        <Text size="xs" ff="monospace" lineClamp={2}>
                          {p.accounts.join(", ")}
                        </Text>
                      </Table.Td>
                      <Table.Td>{formatNumber(p.events)}</Table.Td>
                      <Table.Td>{p.failures > 0 ? <Text c="orange">{formatNumber(p.failures)}</Text> : "0"}</Table.Td>
                      <Table.Td>{p.hosts}</Table.Td>
                      <Table.Td>
                        <Text size="xs">{formatDate(p.last)}</Text>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          </Stack>
        </Tabs.Panel>

        <Tabs.Panel value="suggestions" pt="sm">
          <Stack gap="xs">
            <Text size="sm" c="dimmed">
              Osoby, których nazwy różnią się tylko kropkami, podkreśleniami albo myślnikami (np. <Code>j.kowalski</Code> na VPN
              i <Code>jkowalski</Code> w AD) – prawdopodobnie ta sama osoba. „Połącz” dodaje alias do wybranej nazwy.
            </Text>
            {suggestions.length === 0 && <Text size="sm">Brak podpowiedzi w wybranym okresie.</Text>}
            {suggestions.map((s) => (
              <Group key={s.identities.join("|")} gap="xs">
                {s.identities.map((id) => (
                  <Badge key={id} variant="outline" tt="none">
                    {id}
                  </Badge>
                ))}
                {admin &&
                  s.identities.map((id) => (
                    <Button
                      key={id}
                      size="compact-xs"
                      variant="light"
                      leftSection={<IconLink size={12} />}
                      loading={busy}
                      onClick={async () => {
                        for (const other of s.identities.filter((x) => x !== id)) await addAlias(other, id, "połączone z podpowiedzi");
                        loadPeople();
                      }}
                    >
                      połącz jako {id}
                    </Button>
                  ))}
              </Group>
            ))}
          </Stack>
        </Tabs.Panel>

        <Tabs.Panel value="aliases" pt="sm">
          <Stack gap="xs">
            <Text size="sm" c="dimmed">
              Alias przypisuje konto do osoby, gdy nazwy się różnią – np. login VPN <Code>j.kowalski</Code> → <Code>jkowalski</Code>.
              Alias może być nazwą konta, pełną nazwą <Code>DOMENA\konto</Code> albo adresem <Code>konto@domena</Code>.
            </Text>
            {admin && (
              <Group align="flex-end" gap="xs">
                <TextInput label="Konto" placeholder="j.kowalski" w={220} value={alias} onChange={(e) => setAlias(e.currentTarget.value)} />
                <TextInput label="Osoba" placeholder="jkowalski" w={200} value={target} onChange={(e) => setTarget(e.currentTarget.value)} />
                <TextInput label="Opis" placeholder="login VPN" w={240} value={note} onChange={(e) => setNote(e.currentTarget.value)} />
                <Button loading={busy} disabled={!alias.trim() || !target.trim()} onClick={() => void addAlias(alias, target, note)}>
                  Dodaj alias
                </Button>
              </Group>
            )}
            <Table verticalSpacing={4}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Konto</Table.Th>
                  <Table.Th>Osoba</Table.Th>
                  <Table.Th>Opis</Table.Th>
                  <Table.Th>Dodany</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {aliases.map((a) => (
                  <Table.Tr key={a.alias}>
                    <Table.Td ff="monospace">{a.alias}</Table.Td>
                    <Table.Td>
                      <Anchor component={Link} to={eventsLink(a.identity)} size="sm">
                        {a.identity}
                      </Anchor>
                    </Table.Td>
                    <Table.Td>{a.note}</Table.Td>
                    <Table.Td>
                      <Text size="xs">
                        {a.created_by}, {formatDate(a.created_at)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      {admin && (
                        <Button size="compact-xs" variant="subtle" color="red" leftSection={<IconTrash size={12} />} onClick={() => void removeAlias(a.alias)}>
                          usuń
                        </Button>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Stack>
        </Tabs.Panel>

        <Tabs.Panel value="domains" pt="sm">
          <Stack gap="xs" maw={760}>
            <Text size="sm" c="dimmed">
              Domeny, których konta należą do osób z organizacji – nazwy NetBIOS i DNS (np. <Code>azujo</Code>, <Code>azujo.centrala</Code>,{" "}
              <Code>azujo.pl</Code>). Konta z innych domen – lokalne konta komputerów (<Code>DESKTOP-1\admin</Code>) i goście z innych
              firm – zostają osobnymi tożsamościami z domeną. Pusta lista: każda domena należy do organizacji (konto lokalne „admin” i
              domenowe „admin” to wtedy ta sama osoba).
            </Text>
            {seen.length > 0 && (
              <div>
                <Text size="sm" fw={500}>
                  Domeny kont w zdarzeniach (7 dni)
                </Text>
                <Group gap={6} mt={4}>
                  {seen.map((d) => (
                    <Badge
                      key={d.domain}
                      variant={d.covered ? "light" : "outline"}
                      color={d.covered ? "green" : "orange"}
                      tt="none"
                      style={{ cursor: admin && !domains.includes(d.domain) ? "pointer" : undefined }}
                      title={admin && !domains.includes(d.domain) ? "kliknij, aby dodać do listy (potem Zapisz)" : undefined}
                      onClick={() => admin && !domains.includes(d.domain) && setDomains([...domains, d.domain])}
                    >
                      {d.domain} · {formatNumber(d.events)}
                    </Badge>
                  ))}
                </Group>
                <Text size="xs" c="dimmed" mt={4}>
                  Zielone – na liście; pomarańczowe – poza listą (kliknij, aby dodać). Nazwy komputerów (konta lokalne) zostaw poza listą.
                </Text>
              </div>
            )}
            <TagsInput
              label="Domeny organizacji"
              placeholder="wpisz i naciśnij Enter"
              value={domains}
              onChange={setDomains}
              disabled={!admin}
              splitChars={[",", " ", ";"]}
            />
            {admin && (
              <Group>
                <Button loading={busy} disabled={!domainsChanged} onClick={() => void saveDomains()}>
                  Zapisz domeny
                </Button>
              </Group>
            )}
            <Text fw={600} size="sm" mt="md">
              Sprawdź konto
            </Text>
            <Group align="flex-end" gap="xs">
              <TextInput label="Konto" placeholder="jkowalski, AZUJO\jan, jan@azujo.pl" w={260} value={testUser} onChange={(e) => setTestUser(e.currentTarget.value)} />
              <TextInput label="Domena (opcjonalnie)" placeholder="AZUJO" w={160} value={testDomain} onChange={(e) => setTestDomain(e.currentTarget.value)} />
              <Button variant="default" onClick={() => void test()} disabled={!testUser.trim()}>
                Sprawdź
              </Button>
              {testResult !== null && (
                <Text size="sm">
                  osoba: <b>{testResult || "brak (konto techniczne)"}</b>
                </Text>
              )}
            </Group>
          </Stack>
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
