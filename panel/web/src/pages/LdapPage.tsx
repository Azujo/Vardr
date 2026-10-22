// SPDX-License-Identifier: AGPL-3.0-or-later

// Logowanie domenowe (AD przez LDAPS): połączenie z kontem usługowym,
// kreator grup (OU → grupy → profil uprawnień, w kolejności) i podgląd
// konta – jaki profil dostanie przy logowaniu.
import { useCallback, useEffect, useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Card,
  Code,
  Group,
  Modal,
  PasswordInput,
  Select,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
  Textarea,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconArrowDown, IconArrowUp, IconPlugConnected, IconSearch, IconTrash, IconUsersGroup } from "@tabler/icons-react";
import { api, type LDAPAccountCheck, type LDAPConfig, type LDAPGroup, type Profile } from "../api";
import { useAuth } from "../auth";

const empty: LDAPConfig = {
  enabled: false,
  urls: [],
  ca_pem: "",
  tls_server_name: "",
  bind_dn: "",
  base_dn: "",
  groups_base_dn: "",
  mappings: [],
};

export default function LdapPage() {
  const { can } = useAuth();
  const canEdit = can("users", "write");
  const [available, setAvailable] = useState(true);
  const [cfg, setCfg] = useState<LDAPConfig>(empty);
  const [urlsText, setUrlsText] = useState("");
  const [hasPassword, setHasPassword] = useState(false);
  const [savedEnabled, setSavedEnabled] = useState(false);
  const [bindPassword, setBindPassword] = useState("");
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [groups, setGroups] = useState<LDAPGroup[] | null>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [checkLogin, setCheckLogin] = useState("");
  const [check, setCheck] = useState<LDAPAccountCheck | null>(null);
  const [busy, setBusy] = useState("");
  const [saveOpen, setSaveOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(() => {
    api
      .ldapSettings()
      .then((r) => {
        setAvailable(r.available);
        if (r.config) {
          setCfg(r.config);
          setSavedEnabled(r.config.enabled);
          setUrlsText(r.config.urls.join("\n"));
        }
        setHasPassword(!!r.has_password);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
    api
      .profiles()
      .then((r) => setProfiles(r.profiles))
      .catch(() => setProfiles([]));
  }, []);
  useEffect(load, [load]);

  const draft = (): LDAPConfig => ({
    ...cfg,
    urls: urlsText
      .split(/[\n,]/)
      .map((u) => u.trim())
      .filter(Boolean),
  });
  const run = async (what: string, fn: () => Promise<void>) => {
    setBusy(what);
    try {
      await fn();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy("");
    }
  };
  const profileName = (id: string) => profiles.find((p) => p.id === id)?.name ?? id;
  const mapped = new Map(cfg.mappings.map((m) => [m.sid, m]));
  const setMapping = (g: LDAPGroup, profile: string | null) => {
    const rest = cfg.mappings.filter((m) => m.sid !== g.sid);
    if (!profile) setCfg({ ...cfg, mappings: rest });
    else if (mapped.has(g.sid)) setCfg({ ...cfg, mappings: cfg.mappings.map((m) => (m.sid === g.sid ? { ...m, profile } : m)) });
    else setCfg({ ...cfg, mappings: [...rest, { sid: g.sid, name: g.name, dn: g.dn, profile }] });
  };
  const move = (i: number, d: number) => {
    const m = [...cfg.mappings];
    [m[i], m[i + d]] = [m[i + d], m[i]];
    setCfg({ ...cfg, mappings: m });
  };

  if (!available) {
    return (
      <Alert color="gray" title="Logowanie domenowe niedostępne">
        Wymaga klucza szyfrującego na serwerze (<Code>certs/mfa.key</Code>, tworzy go <Code>deploy.sh config</Code>).
      </Alert>
    );
  }

  return (
    <Stack maw={1100}>
      <div>
        <Title order={2}>Logowanie domenowe</Title>
        <Text c="dimmed" size="sm" maw={860}>
          Konta Active Directory logują się do panelu swoim loginem i hasłem (LDAPS – szyfrowane). Dostęp i profil uprawnień
          wynikają z grup AD: pierwsze pasujące powiązanie na liście decyduje. Członkostwo jest sprawdzane przy logowaniu i co
          5 minut – usunięcie z grupy albo wyłączenie konta w AD kończy sesje. Drugi składnik (TOTP) obowiązuje jak dla kont
          lokalnych; konto lokalne administratora zostaje jako awaryjne.
        </Text>
      </div>
      {error && <Alert color="red">{error}</Alert>}

      <Card withBorder>
        <Stack gap="sm">
          <Group justify="space-between">
            <Title order={4}>1. Połączenie z kontrolerem domeny</Title>
            <Switch
              label={
                (cfg.enabled ? "Logowanie domenowe włączone" : "Logowanie domenowe wyłączone") +
                (cfg.enabled !== savedEnabled ? " (niezapisane)" : "")
              }
              checked={cfg.enabled}
              disabled={!canEdit}
              onChange={(e) => setCfg({ ...cfg, enabled: e.currentTarget.checked })}
            />
          </Group>
          <Group grow align="flex-start">
            <Textarea
              label="Adresy kontrolerów"
              description="ldaps://dc01.firma.pl:636 – po jednym w wierszu (kolejne – zapasowe)"
              autosize
              minRows={2}
              value={urlsText}
              disabled={!canEdit}
              onChange={(e) => setUrlsText(e.currentTarget.value)}
            />
            <TextInput
              label="Nazwa w certyfikacie (opcjonalnie)"
              description="gdy adres to IP albo nazwa spoza certyfikatu kontrolera"
              value={cfg.tls_server_name}
              disabled={!canEdit}
              onChange={(e) => setCfg({ ...cfg, tls_server_name: e.currentTarget.value })}
            />
          </Group>
          <Textarea
            label="Certyfikat CA kontrolerów (PEM)"
            description="np. eksport certyfikatu urzędu z AD CS; puste – zaufane certyfikaty systemu"
            autosize
            minRows={2}
            maxRows={8}
            styles={{ input: { fontFamily: "monospace", fontSize: 11 } }}
            value={cfg.ca_pem}
            disabled={!canEdit}
            onChange={(e) => setCfg({ ...cfg, ca_pem: e.currentTarget.value })}
          />
          <Group grow align="flex-start">
            <TextInput
              label="Konto usługowe"
              description="tylko do odczytu, np. svc-vardr@firma.pl albo jego DN"
              value={cfg.bind_dn}
              disabled={!canEdit}
              onChange={(e) => setCfg({ ...cfg, bind_dn: e.currentTarget.value })}
            />
            <PasswordInput
              label="Hasło konta usługowego"
              description={hasPassword ? "zapisane – wpisz, żeby zmienić" : "zapisywane zaszyfrowane"}
              value={bindPassword}
              disabled={!canEdit}
              onChange={(e) => setBindPassword(e.currentTarget.value)}
            />
            <TextInput
              label="Baza kont"
              description="gdzie szukać kont, np. DC=firma,DC=pl"
              value={cfg.base_dn}
              disabled={!canEdit}
              onChange={(e) => setCfg({ ...cfg, base_dn: e.currentTarget.value })}
            />
          </Group>
          {canEdit && (
            <Group gap="xs">
              <Button
                variant="light"
                leftSection={<IconPlugConnected size={16} />}
                loading={busy === "test"}
                onClick={() =>
                  void run("test", async () => {
                    const r = await api.ldapTest(draft(), bindPassword);
                    setTestResult({ ok: r.ok, text: r.ok ? (r.message ?? "OK") : (r.error ?? "błąd") });
                  })
                }
              >
                Sprawdź połączenie
              </Button>
              {testResult && <Badge color={testResult.ok ? "green" : "red"}>{testResult.ok ? "działa" : "błąd"}</Badge>}
              {testResult && (
                <Text size="xs" c={testResult.ok ? "dimmed" : "red"} maw={600}>
                  {testResult.text}
                </Text>
              )}
            </Group>
          )}
        </Stack>
      </Card>

      <Card withBorder>
        <Stack gap="sm">
          <Title order={4}>2. Grupy i profile</Title>
          <Text size="sm" c="dimmed">
            Utwórz w AD grupy dla panelu we własnym OU (nazwy dowolne), wpisz OU i wybierz profil dla grup. Grupy są
            rozpoznawane po SID – zmiana nazwy w AD niczego nie psuje. Członkostwo zagnieżdżone też się liczy.
          </Text>
          <Group align="flex-end">
            <TextInput
              label="OU z grupami"
              placeholder="OU=Vardr,OU=Grupy,DC=firma,DC=pl"
              w={460}
              value={cfg.groups_base_dn}
              disabled={!canEdit}
              onChange={(e) => setCfg({ ...cfg, groups_base_dn: e.currentTarget.value })}
            />
            {canEdit && (
              <Button
                variant="light"
                leftSection={<IconUsersGroup size={16} />}
                loading={busy === "groups"}
                onClick={() => void run("groups", async () => setGroups((await api.ldapGroups(draft(), bindPassword)).groups))}
              >
                Pokaż grupy
              </Button>
            )}
          </Group>
          {groups && (
            <Table striped verticalSpacing={4}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Grupa</Table.Th>
                  <Table.Th>Członkowie</Table.Th>
                  <Table.Th>Profil w panelu</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {groups.length === 0 && (
                  <Table.Tr>
                    <Table.Td colSpan={3}>
                      <Text size="sm" c="dimmed">
                        Brak grup w tym OU.
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                )}
                {groups.map((g) => (
                  <Table.Tr key={g.sid}>
                    <Table.Td>
                      <Text size="sm" fw={500}>
                        {g.name}
                      </Text>
                      <Text size="xs" c="dimmed">
                        {g.description || g.dn}
                      </Text>
                    </Table.Td>
                    <Table.Td>{g.members}</Table.Td>
                    <Table.Td>
                      <Select
                        size="xs"
                        w={220}
                        placeholder="— bez dostępu —"
                        clearable
                        disabled={!canEdit}
                        data={profiles.map((p) => ({ value: p.id, label: p.name }))}
                        value={mapped.get(g.sid)?.profile ?? null}
                        onChange={(v) => setMapping(g, v)}
                      />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          )}
          <Text size="sm" fw={500}>
            Powiązania (kolejność decyduje – pierwsze pasujące):
          </Text>
          {cfg.mappings.length === 0 ? (
            <Text size="sm" c="dimmed">
              Brak – żadne konto domenowe nie zaloguje się do panelu.
            </Text>
          ) : (
            <Stack gap={4}>
              {cfg.mappings.map((m, i) => (
                <Group key={m.sid} gap="xs">
                  <Badge variant="light" w={28} p={0}>
                    {i + 1}
                  </Badge>
                  <Text size="sm" w={260} truncate>
                    {m.name}
                  </Text>
                  <Text size="sm">→</Text>
                  <Badge color={profiles.find((p) => p.id === m.profile)?.admin ? "grape" : "blue"} variant="light">
                    {profileName(m.profile)}
                  </Badge>
                  {canEdit && (
                    <>
                      <ActionIcon variant="subtle" disabled={i === 0} onClick={() => move(i, -1)} aria-label="wyżej">
                        <IconArrowUp size={14} />
                      </ActionIcon>
                      <ActionIcon variant="subtle" disabled={i === cfg.mappings.length - 1} onClick={() => move(i, 1)} aria-label="niżej">
                        <IconArrowDown size={14} />
                      </ActionIcon>
                      <Tooltip label="usuń powiązanie">
                        <ActionIcon
                          variant="subtle"
                          color="red"
                          onClick={() => setCfg({ ...cfg, mappings: cfg.mappings.filter((x) => x.sid !== m.sid) })}
                        >
                          <IconTrash size={14} />
                        </ActionIcon>
                      </Tooltip>
                    </>
                  )}
                  <Text size="xs" c="dimmed" ff="monospace">
                    {m.sid}
                  </Text>
                </Group>
              ))}
            </Stack>
          )}
        </Stack>
      </Card>

      {canEdit && (
        <Card withBorder>
          <Stack gap="sm">
            <Title order={4}>3. Sprawdzenie konta</Title>
            <Group align="flex-end">
              <TextInput
                label="Login domenowy"
                placeholder="jan.kowalski"
                w={260}
                value={checkLogin}
                onChange={(e) => setCheckLogin(e.currentTarget.value)}
              />
              <Button
                variant="light"
                leftSection={<IconSearch size={16} />}
                loading={busy === "check"}
                disabled={!checkLogin}
                onClick={() => void run("check", async () => setCheck(await api.ldapCheck(draft(), bindPassword, checkLogin)))}
              >
                Sprawdź (bez hasła)
              </Button>
            </Group>
            {check && !check.found && <Alert color="orange">Nie ma takiego konta w bazie kont.</Alert>}
            {check?.found && check.account && (
              <Alert color={check.profile ? "green" : "orange"}>
                <Text size="sm">
                  <b>{check.account.display_name || check.account.login}</b> ({check.account.upn || check.account.login})
                  {check.account.disabled && " – konto wyłączone w AD"}; grup zabezpieczeń: {check.groups}.
                </Text>
                <Text size="sm">
                  {check.profile
                    ? `Przy logowaniu dostanie profil „${profileName(check.profile)}” (grupa ${check.matched[0]?.name}).`
                    : "Nie zaloguje się – nie należy do żadnej grupy z powiązania."}
                  {check.matched.length > 1 && ` Pasuje też: ${check.matched.slice(1).map((m) => m.name).join(", ")}.`}
                </Text>
              </Alert>
            )}
          </Stack>
        </Card>
      )}

      {canEdit && (
        <Group>
          <Button
            onClick={() => {
              setPassword("");
              setSaveOpen(true);
            }}
          >
            Zapisz ustawienia
          </Button>
        </Group>
      )}

      <Modal opened={saveOpen} onClose={() => setSaveOpen(false)} title="Zapis ustawień logowania domenowego" centered>
        <Stack>
          <Text size="sm">Zmiana trafi do audytu (bez haseł) i działa od razu.</Text>
          <PasswordInput label="Twoje hasło" value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoFocus />
          <Button
            loading={busy === "save"}
            disabled={!password}
            onClick={() =>
              void run("save", async () => {
                await api.saveLdapSettings(draft(), bindPassword, password);
                notifications.show({ color: "green", message: "Zapisano ustawienia logowania domenowego" });
                setSaveOpen(false);
                setBindPassword("");
                load();
              })
            }
          >
            Zapisz
          </Button>
        </Stack>
      </Modal>
    </Stack>
  );
}
