// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import {
  Alert as MAlert,
  Anchor,
  Badge,
  Button,
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
import { useTranslation } from "react-i18next";
import i18n from "../i18n";
import { useAuth } from "../auth";

function err(e: unknown) {
  notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
}

// Wynik zapisu: dostarczenie zmiany do normalizatorów (ok, no_nats, failed).
function saved(r: { delivery: string }) {
  notifications.show({
    color: r.delivery === "ok" ? "green" : "orange",
    message: i18n.t(`identities:saved.${r.delivery}`, { defaultValue: i18n.t("identities:saved.ok") }),
  });
}

function eventsLink(identity: string) {
  const v = /[\s"]/.test(identity) ? `"${identity.replace(/"/g, "")}"` : identity;
  return `/events?q=${encodeURIComponent(`identity:${v}`)}`;
}

export default function IdentitiesPage() {
  const { t } = useTranslation("identities");
  const { can } = useAuth();
  const admin = can("identities", "write");
  const [tab, setTab] = useState<string | null>("people");
  const [domains, setDomains] = useState<string[]>([]);
  const [savedDomains, setSavedDomains] = useState<string[]>([]);
  const [shared, setShared] = useState<string[]>([]);
  const [savedShared, setSavedShared] = useState<string[]>([]);
  const [testHost, setTestHost] = useState("");
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
        setShared(r.shared);
        setSavedShared(r.shared);
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
      saved(await identitiesApi.setDomains(domains));
      loadConfig();
    } catch (e) {
      err(e);
    } finally {
      setBusy(false);
    }
  };
  const saveShared = async () => {
    setBusy(true);
    try {
      saved(await identitiesApi.setShared(shared));
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
      saved(await identitiesApi.setAlias(a, id, n));
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
      saved(await identitiesApi.deleteAlias(a));
      loadConfig();
    } catch (e) {
      err(e);
    }
  };
  const test = async () => {
    try {
      setTestResult((await identitiesApi.resolve(testUser, testDomain, testHost)).identity);
    } catch (e) {
      err(e);
    }
  };
  const domainsChanged = domains.join(",") !== savedDomains.join(",");
  const sharedChanged = shared.join(",") !== savedShared.join(",");

  return (
    <Stack>
      <div>
        <Title order={2}>{t("title")}</Title>
        <Text c="dimmed" size="sm" maw={900}>
          {t("intro")}
        </Text>
      </div>
      {error && <MAlert color="red">{error}</MAlert>}
      {uncovered.length > 0 && (
        <MAlert color="orange" title={t("uncovered.title")}>
          {t("uncovered.text", { list: uncovered.map((d) => `${d.domain} (${formatNumber(d.events)})`).join(", ") })}
        </MAlert>
      )}
      {!delivery && (
        <MAlert color="orange">{t("noNats")}</MAlert>
      )}
      <Tabs value={tab} onChange={setTab}>
        <Tabs.List>
          <Tabs.Tab value="people">{t("tab.people")}</Tabs.Tab>
          <Tabs.Tab value="suggestions">
            {t("tab.suggestions")} {suggestions.length > 0 && <Badge size="xs">{suggestions.length}</Badge>}
          </Tabs.Tab>
          <Tabs.Tab value="aliases">{t("tab.aliases", { count: aliases.length })}</Tabs.Tab>
          <Tabs.Tab value="domains">{t("tab.domains")}</Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="people" pt="sm">
          <Stack gap="xs">
            <Group align="flex-end" gap="xs">
              <Select
                label={t("people.period")}
                w={160}
                allowDeselect={false}
                value={hours}
                onChange={(v) => setHours(v ?? "168")}
                data={[
                  { value: "24", label: t("people.h24") },
                  { value: "168", label: t("people.d7") },
                  { value: "720", label: t("people.d30") },
                ]}
              />
              <TextInput label={t("people.search")} placeholder={t("people.searchPlaceholder")} w={240} value={q} onChange={(e) => setQ(e.currentTarget.value)} />
            </Group>
            <Text size="xs" c="dimmed">
              {t("people.hint")}
            </Text>
            <Table.ScrollContainer minWidth={900}>
              <Table striped verticalSpacing="xs">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t("col.person")}</Table.Th>
                    <Table.Th>{t("col.sources")}</Table.Th>
                    <Table.Th>{t("col.accounts")}</Table.Th>
                    <Table.Th>{t("col.events")}</Table.Th>
                    <Table.Th>{t("col.failures")}</Table.Th>
                    <Table.Th>{t("col.hosts")}</Table.Th>
                    <Table.Th>{t("col.last")}</Table.Th>
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
              {t("suggestions.hint")}
            </Text>
            {suggestions.length === 0 && <Text size="sm">{t("suggestions.none")}</Text>}
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
                        for (const other of s.identities.filter((x) => x !== id)) await addAlias(other, id, t("suggestions.note"));
                        loadPeople();
                      }}
                    >
                      {t("suggestions.merge", { id })}
                    </Button>
                  ))}
              </Group>
            ))}
          </Stack>
        </Tabs.Panel>

        <Tabs.Panel value="aliases" pt="sm">
          <Stack gap="xs">
            <Text size="sm" c="dimmed">
              {t("aliases.hint")}
            </Text>
            {admin && (
              <Group align="flex-end" gap="xs">
                <TextInput label={t("col.account")} placeholder="j.kowalski" w={220} value={alias} onChange={(e) => setAlias(e.currentTarget.value)} />
                <TextInput label={t("col.person")} placeholder="jkowalski" w={200} value={target} onChange={(e) => setTarget(e.currentTarget.value)} />
                <TextInput label={t("col.note")} placeholder={t("aliases.notePlaceholder")} w={240} value={note} onChange={(e) => setNote(e.currentTarget.value)} />
                <Button loading={busy} disabled={!alias.trim() || !target.trim()} onClick={() => void addAlias(alias, target, note)}>
                  {t("aliases.add")}
                </Button>
              </Group>
            )}
            <Table verticalSpacing={4}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t("col.account")}</Table.Th>
                  <Table.Th>{t("col.person")}</Table.Th>
                  <Table.Th>{t("col.note")}</Table.Th>
                  <Table.Th>{t("col.added")}</Table.Th>
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
                          {t("aliases.remove")}
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
              {t("domains.hint")}
            </Text>
            {seen.length > 0 && (
              <div>
                <Text size="sm" fw={500}>
                  {t("domains.seen")}
                </Text>
                <Group gap={6} mt={4}>
                  {seen.map((d) => (
                    <Badge
                      key={d.domain}
                      variant={d.covered ? "light" : "outline"}
                      color={d.covered ? "green" : "orange"}
                      tt="none"
                      style={{ cursor: admin && !domains.includes(d.domain) ? "pointer" : undefined }}
                      title={admin && !domains.includes(d.domain) ? t("domains.clickToAdd") : undefined}
                      onClick={() => admin && !domains.includes(d.domain) && setDomains([...domains, d.domain])}
                    >
                      {d.domain} · {formatNumber(d.events)}
                    </Badge>
                  ))}
                </Group>
                <Text size="xs" c="dimmed" mt={4}>
                  {t("domains.legend")}
                </Text>
              </div>
            )}
            <TagsInput
              label={t("domains.label")}
              placeholder={t("domains.enter")}
              value={domains}
              onChange={setDomains}
              disabled={!admin}
              splitChars={[",", " ", ";"]}
            />
            {admin && (
              <Group>
                <Button loading={busy} disabled={!domainsChanged} onClick={() => void saveDomains()}>
                  {t("domains.save")}
                </Button>
              </Group>
            )}
            <Text fw={600} size="sm" mt="md">
              {t("shared.title")}
            </Text>
            <Text size="sm" c="dimmed">
              {t("shared.hint")}
            </Text>
            <TagsInput
              label={t("shared.label")}
              placeholder={t("domains.enter")}
              value={shared}
              onChange={setShared}
              disabled={!admin}
              splitChars={[",", " ", ";"]}
            />
            {admin && (
              <Group>
                <Button loading={busy} disabled={!sharedChanged} onClick={() => void saveShared()}>
                  {t("shared.save")}
                </Button>
              </Group>
            )}
            <Text fw={600} size="sm" mt="md">
              {t("check.title")}
            </Text>
            <Group align="flex-end" gap="xs">
              <TextInput label={t("col.account")} placeholder="jkowalski, AZUJO\jan, jan@azujo.pl" w={260} value={testUser} onChange={(e) => setTestUser(e.currentTarget.value)} />
              <TextInput label={t("check.domain")} placeholder="AZUJO" w={160} value={testDomain} onChange={(e) => setTestDomain(e.currentTarget.value)} />
              <TextInput label={t("check.device")} placeholder="MikroTik" w={160} value={testHost} onChange={(e) => setTestHost(e.currentTarget.value)} />
              <Button variant="default" onClick={() => void test()} disabled={!testUser.trim()}>
                {t("check.run")}
              </Button>
              {testResult !== null && (
                <Text size="sm">
                  {t("check.result")} <b>{testResult || t("check.technical")}</b>
                </Text>
              )}
            </Group>
          </Stack>
        </Tabs.Panel>
      </Tabs>
    </Stack>
  );
}
