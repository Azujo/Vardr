// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert as MAlert,
  Badge,
  Button,
  Card,
  Checkbox,
  Code,
  CopyButton,
  Group,
  Modal,
  NumberInput,
  PasswordInput,
  Radio,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  TextInput,
  Textarea,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCopy, IconDeviceFloppy, IconKey, IconPlayerPlay, IconPlugConnected } from "@tabler/icons-react";
import RestorePanel from "./BackupRestore";
import {
  ApiError,
  backupApi,
  formatBytes,
  formatDate,
  type BackupConfig,
  type BackupMethod,
  type BackupRun,
  type BackupView,
} from "../api";

// Kopie zapasowe: ustawienia dla usługi siem-backup, zlecenia i historia.

const weekdays = ["poniedziałek", "wtorek", "środa", "czwartek", "piątek", "sobota", "niedziela"].map((l, i) => ({
  value: String(i + 1),
  label: l,
}));

const runStatus: Record<BackupRun["status"], { label: string; color: string }> = {
  running: { label: "w toku", color: "blue" },
  ok: { label: "udana", color: "green" },
  partial: { label: "bez wysyłki", color: "orange" },
  error: { label: "nieudana", color: "red" },
};

const methodLabels: Record<BackupMethod, string> = {
  none: "Tylko lokalnie",
  sftp: "SFTP (SSH)",
  smb: "SMB (udział Windows / NAS)",
  s3: "S3 (MinIO, AWS, Backblaze…)",
};

function err(e: unknown) {
  notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
}

function pad(n: number) {
  return String(n).padStart(2, "0");
}

function scheduleText(c: BackupConfig): string {
  const s = c.schedule;
  const at = `${pad(s.hour)}:${pad(s.minute)}`;
  if (!c.enabled) return "wyłączone";
  if (s.kind === "hours") return `co ${s.every_hours} h (minuta ${pad(s.minute)})`;
  if (s.kind === "weekly") return `co tydzień: ${weekdays[(s.weekday ?? 1) - 1]?.label} ${at}`;
  return `codziennie o ${at}`;
}

export default function BackupPage() {
  const [view, setView] = useState<BackupView | null>(null);
  const [cfg, setCfg] = useState<BackupConfig | null>(null);
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [confirm, setConfirm] = useState(false);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState("settings");

  const load = useCallback(async (resetForm: boolean) => {
    try {
      const v = await backupApi.get();
      setView(v);
      if (resetForm) {
        setCfg(structuredClone(v.state.config));
        setSecrets({});
      }
    } catch (e) {
      err(e);
    }
  }, []);
  useEffect(() => void load(true), [load]);

  const pending = !!view?.state.requests.some((r) => !r.done_at) || !!view?.state.runs.some((r) => r.status === "running");
  useEffect(() => {
    const t = setInterval(() => void load(false), pending ? 4000 : 30000);
    return () => clearInterval(t);
  }, [load, pending]);

  // Wynik zlecenia z panelu – powiadomienie, gdy się zakończy.
  const [watching, setWatching] = useState<number[]>([]);
  useEffect(() => {
    if (!view) return;
    for (const id of watching) {
      const r = view.state.requests.find((x) => x.id === id);
      if (r?.done_at) {
        notifications.show({ color: r.ok ? "green" : "red", autoClose: r.ok ? 8000 : false, message: r.message || (r.ok ? "gotowe" : "nieudane") });
        setWatching((w) => w.filter((x) => x !== id));
      }
    }
  }, [view, watching]);

  const dirty = useMemo(
    () => !!view && !!cfg && (JSON.stringify(cfg) !== JSON.stringify(view.state.config) || Object.values(secrets).some((v) => v.trim() !== "")),
    [view, cfg, secrets],
  );

  if (!view || !cfg) return <Text c="dimmed">Wczytywanie…</Text>;
  const st = view.state;
  const runner = st.runner;
  const t = cfg.target;
  const set = (f: (c: BackupConfig) => void) =>
    setCfg((c) => {
      const n = structuredClone(c!);
      f(n);
      return n;
    });
  const secretSet = (name: string) => st.secrets.some((s) => s.name === name) && !view.stale_secrets.includes(name);
  const secretHint = (name: string) =>
    view.stale_secrets.includes(name)
      ? "zapisany starym kluczem usługi – wpisz ponownie"
      : secretSet(name)
        ? "zapisany – wpisz, aby zmienić"
        : "";

  const ask = async (action: "run" | "test" | "genkey" | "list" | "inspect", file?: { location: string; name: string }) => {
    try {
      const r = await backupApi.request(action, file);
      setWatching((w) => [...w, r.request.id]);
      notifications.show({ message: "zlecono – usługa kopii wykona je w ciągu kilkunastu sekund" });
      void load(false);
    } catch (e) {
      err(e);
    }
  };

  const save = async () => {
    setBusy(true);
    try {
      const r = await backupApi.save(cfg, secrets, password);
      notifications.show({ color: "green", message: r.message });
      setConfirm(false);
      setPassword("");
      await load(true);
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) setPassword("");
      err(e);
    } finally {
      setBusy(false);
    }
  };

  const restoring = st.requests.some((r) => r.action === "restore" && !r.done_at);
  const last = st.runs.find((r) => r.status !== "running");
  const lastOK = st.runs.find((r) => r.status === "ok" || r.status === "partial");

  return (
    <Stack>
      <div>
        <Title order={2}>Kopie zapasowe</Title>
        <Text c="dimmed" size="sm">
          Kopie wykonuje usługa siem-backup na serwerze. Każda kopia jest szyfrowana hasłem kopii, które zna tylko administrator
          serwera – panel go nie przechowuje. Hasła i klucze do miejsca docelowego panel szyfruje kluczem usługi kopii; po zapisie
          nie da się ich odczytać, tylko zastąpić.
        </Text>
      </div>

      {!view.online && (
        <MAlert color="red" title="Usługa kopii nie odpowiada">
          {runner?.seen_at
            ? `Ostatni kontakt: ${formatDate(runner.seen_at)}. Kopie z harmonogramu nie powstają.`
            : "Usługa siem-backup jeszcze się nie zgłosiła (kontener backup na serwerze)."}
        </MAlert>
      )}
      {runner && !runner.pass_id && (
        <MAlert color="red" title="Brak hasła kopii">
          Bez hasła kopie nie powstają. Administrator serwera ustawia je raz poleceniem <Code>./backup.sh haslo init</Code> w katalogu
          stosu i zapisuje poza serwerem.
        </MAlert>
      )}

      <SimpleGrid cols={{ base: 1, md: 3 }}>
        <Card withBorder>
          <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
            Ostatnia kopia
          </Text>
          {last ? (
            <>
              <Group gap="xs" mt={4}>
                <Badge color={runStatus[last.status].color}>{runStatus[last.status].label}</Badge>
                <Text size="sm">{formatDate(last.started_at)}</Text>
              </Group>
              {lastOK && lastOK.id !== last.id && (
                <Text size="xs" c="dimmed" mt={4}>
                  ostatnia udana: {formatDate(lastOK.started_at)}
                </Text>
              )}
            </>
          ) : (
            <Text size="sm" mt={4}>
              jeszcze żadnej
            </Text>
          )}
          <Text size="xs" c="dimmed" mt={4}>
            harmonogram: {scheduleText(st.config)}
          </Text>
        </Card>
        <Card withBorder>
          <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
            Usługa kopii
          </Text>
          <Group gap="xs" mt={4}>
            <Badge color={view.online ? "green" : "red"}>{view.online ? "działa" : "nie odpowiada"}</Badge>
            {runner?.version && <Text size="xs" c="dimmed">{runner.version}</Text>}
          </Group>
          <Tooltip
            multiline
            w={320}
            label="Skrót hasła szyfrującego kopie – nie samo hasło. Ten sam identyfikator jest w nazwie każdej kopii, więc widać, którym hasłem ją otworzyć. Hasło zna tylko administrator serwera (./backup.sh haslo pokaz)."
          >
            <Text size="xs" c="dimmed" mt={4} style={{ cursor: "help" }}>
              identyfikator hasła kopii: {runner?.pass_id ? <Code>{runner.pass_id}</Code> : "brak hasła"}
            </Text>
          </Tooltip>
          {runner?.local_dir && (
            <Text size="xs" c="dimmed">
              lokalnie: {runner.local_dir} (wolne {formatBytes(runner.local_free)})
            </Text>
          )}
        </Card>
        <Card withBorder>
          <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
            Działania
          </Text>
          <Stack gap={6} mt={6}>
            <Button size="xs" leftSection={<IconPlayerPlay size={14} />} disabled={!view.online} onClick={() => void ask("run")}>
              Zrób kopię teraz
            </Button>
            <Tooltip label={dirty ? "najpierw zapisz zmiany" : "zapis i odczyt w miejscu docelowym"}>
              <Button
                size="xs"
                variant="light"
                leftSection={<IconPlugConnected size={14} />}
                disabled={!view.online || dirty || st.config.target.method === "none"}
                onClick={() => void ask("test")}
              >
                Sprawdź połączenie
              </Button>
            </Tooltip>
          </Stack>
        </Card>
      </SimpleGrid>

      <Tabs value={tab} onChange={(v) => setTab(v ?? "settings")}>
        <Tabs.List>
          <Tabs.Tab value="settings">Ustawienia</Tabs.Tab>
          <Tabs.Tab value="history">Historia ({st.runs.length})</Tabs.Tab>
          <Tabs.Tab value="restore" color="red">
            Przywracanie {restoring && <Badge size="xs" color="red">w toku</Badge>}
          </Tabs.Tab>
        </Tabs.List>

        <Tabs.Panel value="settings" pt="md">
          <Stack>
          <Card withBorder>
            <Group justify="space-between" mb="xs">
              <Title order={4}>Harmonogram</Title>
              <Switch label="Kopie z harmonogramu włączone" checked={cfg.enabled} onChange={(e) => set((c) => (c.enabled = e.currentTarget.checked))} />
            </Group>
            <Group align="flex-end">
              <SegmentedControl
                value={cfg.schedule.kind}
                onChange={(v) =>
                  set((c) => {
                    c.schedule.kind = v as BackupConfig["schedule"]["kind"];
                    if (v === "hours" && !c.schedule.every_hours) c.schedule.every_hours = 6;
                    if (v === "weekly" && !c.schedule.weekday) c.schedule.weekday = 7;
                  })
                }
                data={[
                  { value: "hours", label: "co kilka godzin" },
                  { value: "daily", label: "codziennie" },
                  { value: "weekly", label: "co tydzień" },
                ]}
              />
              {cfg.schedule.kind === "hours" && (
                <Select
                  label="Co ile godzin"
                  w={140}
                  allowDeselect={false}
                  value={String(cfg.schedule.every_hours ?? 6)}
                  onChange={(v) => set((c) => (c.schedule.every_hours = Number(v)))}
                  data={["1", "2", "3", "4", "6", "8", "12"]}
                />
              )}
              {cfg.schedule.kind === "weekly" && (
                <Select
                  label="Dzień"
                  w={160}
                  allowDeselect={false}
                  value={String(cfg.schedule.weekday ?? 7)}
                  onChange={(v) => set((c) => (c.schedule.weekday = Number(v)))}
                  data={weekdays}
                />
              )}
              {cfg.schedule.kind !== "hours" && (
                <NumberInput label="Godzina" w={100} min={0} max={23} value={cfg.schedule.hour} onChange={(v) => set((c) => (c.schedule.hour = Number(v) || 0))} />
              )}
              <NumberInput label="Minuta" w={100} min={0} max={59} value={cfg.schedule.minute} onChange={(v) => set((c) => (c.schedule.minute = Number(v) || 0))} />
            </Group>
            <Text size="xs" c="dimmed" mt="xs">
              Czas serwera (Europe/Warsaw). Kopia, której termin minął przy wyłączonym serwerze, wykona się po jego starcie.
            </Text>
          </Card>

          <Card withBorder>
            <Title order={4} mb="xs">
              Zawartość
            </Title>
            <Stack gap="xs">
              <Checkbox
                label="Baza Saga"
                description="konta i role, agenci i ich certyfikaty, grupy, alerty, reguły z panelu, spis archiwum NIS2, polityki, kanały powiadomień"
                checked={cfg.include.saga}
                onChange={(e) => set((c) => (c.include.saga = e.currentTarget.checked))}
              />
              <Checkbox
                label="Konfiguracja serwera"
                description="certyfikaty (z kluczem CA agentów) i plik .env z hasłami usług"
                checked={cfg.include.config}
                onChange={(e) => set((c) => (c.include.config = e.currentTarget.checked))}
              />
              <Checkbox
                label="Archiwum NIS2 (przyrosty)"
                description="nowe segmenty i manifesty od poprzedniej kopii – wysyłane tylko do miejsca docelowego (archiwum jest już na dysku serwera)"
                checked={cfg.include.archive}
                onChange={(e) => set((c) => (c.include.archive = e.currentTarget.checked))}
              />
              <Checkbox
                label="Dane Grafany"
                description="pulpity i ustawienia zmienione w interfejsie Grafany (pulpity z repozytorium są odtwarzane bez kopii)"
                checked={cfg.include.grafana}
                onChange={(e) => set((c) => (c.include.grafana = e.currentTarget.checked))}
              />
              {(!cfg.include.saga || !cfg.include.config) && (
                <MAlert color="orange">
                  Bez bazy Saga i konfiguracji serwera nie da się odtworzyć systemu po utracie serwera: agenci straciliby zaufanie do
                  nowego serwera, a konta i ustawienia trzeba by tworzyć od nowa.
                </MAlert>
              )}
              <Text size="xs" c="dimmed">
                Zdarzenia z ClickHouse nie są kopiowane – po odtworzeniu serwera ostatnie dni odtwarza się z archiwum NIS2 (Urd →
                Odtworzenie).
              </Text>
            </Stack>
          </Card>

          <Card withBorder>
            <Title order={4} mb="xs">
              Retencja
            </Title>
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <Stack gap={4}>
                <Text size="sm" fw={500}>
                  Na serwerze
                </Text>
                <Group>
                  <NumberInput label="Dni" w={120} min={1} max={3650} value={cfg.local.keep_days} onChange={(v) => set((c) => (c.local.keep_days = Number(v) || 1))} />
                  <NumberInput
                    label="Najwyżej kopii"
                    description="0 – bez limitu"
                    w={140}
                    min={0}
                    max={1000}
                    value={cfg.local.keep_count}
                    onChange={(v) => set((c) => (c.local.keep_count = Number(v) || 0))}
                  />
                </Group>
              </Stack>
              <Stack gap={4}>
                <Text size="sm" fw={500} c={t.method === "none" ? "dimmed" : undefined}>
                  W miejscu docelowym
                </Text>
                <Group>
                  <NumberInput
                    label="Dni"
                    w={120}
                    min={1}
                    max={3650}
                    disabled={t.method === "none"}
                    value={cfg.remote.keep_days}
                    onChange={(v) => set((c) => (c.remote.keep_days = Number(v) || 1))}
                  />
                  <NumberInput
                    label="Najwyżej kopii"
                    description="0 – bez limitu"
                    w={140}
                    min={0}
                    max={1000}
                    disabled={t.method === "none"}
                    value={cfg.remote.keep_count}
                    onChange={(v) => set((c) => (c.remote.keep_count = Number(v) || 0))}
                  />
                </Group>
              </Stack>
            </SimpleGrid>
            <Text size="xs" c="dimmed" mt="xs">
              Kopia jest usuwana, gdy jest starsza niż podana liczba dni albo gdy jest więcej kopii niż limit. Najnowsza kopia zostaje
              zawsze. Paczki archiwum NIS2 w miejscu docelowym wygasają tylko po dniach.
            </Text>
          </Card>

          <Card withBorder>
            <Title order={4} mb="xs">
              Miejsce docelowe
            </Title>
            <Stack gap="sm">
              <Select
                w={320}
                allowDeselect={false}
                value={t.method}
                onChange={(v) =>
                  set((c) => {
                    c.target = { method: v as BackupMethod, auth: v === "sftp" ? "server_key" : undefined };
                  })
                }
                data={(Object.keys(methodLabels) as BackupMethod[]).map((m) => ({ value: m, label: methodLabels[m] }))}
              />
              {t.method === "none" && (
                <MAlert color="orange">
                  Kopie zostają tylko na dysku tego serwera – awaria serwera albo jego dysku zabierze je razem z systemem.
                </MAlert>
              )}
              {(t.method === "sftp" || t.method === "smb") && (
                <Group align="flex-end">
                  <TextInput label="Serwer" placeholder="192.168.88.180" w={220} value={t.host ?? ""} onChange={(e) => set((c) => (c.target.host = e.currentTarget.value))} />
                  <NumberInput
                    label="Port"
                    placeholder={t.method === "sftp" ? "22" : "445"}
                    w={100}
                    min={1}
                    max={65535}
                    value={t.port || ""}
                    onChange={(v) => set((c) => (c.target.port = Number(v) || undefined))}
                  />
                  <TextInput label="Użytkownik" w={180} value={t.user ?? ""} onChange={(e) => set((c) => (c.target.user = e.currentTarget.value))} />
                  {t.method === "smb" && (
                    <>
                      <TextInput label="Udział" placeholder="kopie" w={160} value={t.share ?? ""} onChange={(e) => set((c) => (c.target.share = e.currentTarget.value))} />
                      <TextInput label="Domena (opcjonalnie)" w={160} value={t.domain ?? ""} onChange={(e) => set((c) => (c.target.domain = e.currentTarget.value))} />
                    </>
                  )}
                </Group>
              )}
              {t.method === "s3" && (
                <Group align="flex-end">
                  <TextInput
                    label="Adres usługi"
                    description="puste – Amazon S3"
                    placeholder="https://minio.firma.local:9000"
                    w={300}
                    value={t.endpoint ?? ""}
                    onChange={(e) => set((c) => (c.target.endpoint = e.currentTarget.value))}
                  />
                  <TextInput label="Region" placeholder="eu-central-1" w={150} value={t.region ?? ""} onChange={(e) => set((c) => (c.target.region = e.currentTarget.value))} />
                  <TextInput label="Kubełek" w={200} value={t.bucket ?? ""} onChange={(e) => set((c) => (c.target.bucket = e.currentTarget.value))} />
                  <TextInput label="Identyfikator klucza" w={220} value={t.access_key ?? ""} onChange={(e) => set((c) => (c.target.access_key = e.currentTarget.value))} />
                </Group>
              )}
              {t.method !== "none" && (
                <TextInput
                  label="Katalog"
                  description={
                    t.method === "sftp"
                      ? "zaczynający się od / – ścieżka bezwzględna, inaczej względem katalogu domowego użytkownika"
                      : t.method === "smb"
                        ? "katalog w udziale (puste – główny katalog udziału)"
                        : "prefiks w kubełku (puste – główny)"
                  }
                  placeholder={t.method === "sftp" ? "/mnt/tank/vardr_backup" : "vardr"}
                  maw={520}
                  value={t.path ?? ""}
                  onChange={(e) => set((c) => (c.target.path = e.currentTarget.value))}
                />
              )}

              {t.method === "sftp" && (
                <Radio.Group label="Logowanie" value={t.auth ?? "server_key"} onChange={(v) => set((c) => (c.target.auth = v as typeof t.auth))}>
                  <Stack gap={6} mt={4}>
                    <Radio value="server_key" label="Klucz SSH wygenerowany przez usługę kopii (zalecane – klucz prywatny nie opuszcza serwera)" />
                    <Radio value="private_key" label="Własny klucz prywatny SSH" />
                    <Radio value="password" label="Hasło" />
                  </Stack>
                </Radio.Group>
              )}
              {t.method === "sftp" && t.auth === "server_key" && (
                <Stack gap={4}>
                  {runner?.ssh_public_key ? (
                    <>
                      <Text size="sm">
                        Dopisz ten klucz publiczny do <Code>~/.ssh/authorized_keys</Code> użytkownika na serwerze kopii (w TrueNAS: konto
                        użytkownika → klucz publiczny SSH):
                      </Text>
                      <Group gap="xs" wrap="nowrap" align="flex-start">
                        <Code block style={{ wordBreak: "break-all", flex: 1 }}>
                          {runner.ssh_public_key}
                        </Code>
                        <CopyButton value={runner.ssh_public_key}>
                          {({ copied, copy }) => (
                            <Button size="xs" variant="light" leftSection={<IconCopy size={14} />} onClick={copy}>
                              {copied ? "skopiowano" : "kopiuj"}
                            </Button>
                          )}
                        </CopyButton>
                      </Group>
                    </>
                  ) : (
                    <Text size="sm" c="orange">
                      Usługa kopii nie ma jeszcze klucza SSH – wygeneruj go.
                    </Text>
                  )}
                  <Group>
                    <Button
                      size="xs"
                      variant="default"
                      leftSection={<IconKey size={14} />}
                      disabled={!view.online}
                      onClick={() => {
                        if (!runner?.ssh_public_key || window.confirm("Nowy klucz zastąpi obecny – stary przestanie działać. Kontynuować?")) void ask("genkey");
                      }}
                    >
                      {runner?.ssh_public_key ? "Wygeneruj nowy klucz" : "Wygeneruj klucz"}
                    </Button>
                  </Group>
                </Stack>
              )}
              {t.method === "sftp" && t.auth === "private_key" && (
                <Textarea
                  label="Klucz prywatny SSH"
                  description={secretHint("private_key") || "format OpenSSH albo PEM, bez hasła"}
                  placeholder={secretSet("private_key") ? "••••••••" : "-----BEGIN OPENSSH PRIVATE KEY-----"}
                  autosize
                  minRows={3}
                  maxRows={10}
                  spellCheck={false}
                  styles={{ input: { fontFamily: "monospace", fontSize: 11 } }}
                  value={secrets.private_key ?? ""}
                  onChange={(e) => setSecrets((s) => ({ ...s, private_key: e.currentTarget.value }))}
                />
              )}
              {((t.method === "sftp" && t.auth === "password") || t.method === "smb") && (
                <PasswordInput
                  label="Hasło"
                  description={secretHint("password")}
                  placeholder={secretSet("password") ? "••••••••" : ""}
                  w={320}
                  autoComplete="new-password"
                  value={secrets.password ?? ""}
                  onChange={(e) => setSecrets((s) => ({ ...s, password: e.currentTarget.value }))}
                />
              )}
              {t.method === "s3" && (
                <PasswordInput
                  label="Klucz tajny (secret access key)"
                  description={secretHint("s3_secret")}
                  placeholder={secretSet("s3_secret") ? "••••••••" : ""}
                  w={360}
                  autoComplete="new-password"
                  value={secrets.s3_secret ?? ""}
                  onChange={(e) => setSecrets((s) => ({ ...s, s3_secret: e.currentTarget.value }))}
                />
              )}
              {t.method === "sftp" && runner?.host_key && (
                <Text size="xs" c="dimmed">
                  Zapamiętany klucz serwera kopii: <Code>{runner.host_key}</Code> – jego zmiana zatrzyma wysyłkę (ochrona przed podszyciem).
                </Text>
              )}
            </Stack>
          </Card>

          <Group>
            <Button leftSection={<IconDeviceFloppy size={16} />} disabled={!dirty} onClick={() => setConfirm(true)}>
              Zapisz ustawienia
            </Button>
            {dirty && (
              <Button variant="subtle" onClick={() => void load(true)}>
                Cofnij zmiany
              </Button>
            )}
            {st.updated_at && (
              <Text size="xs" c="dimmed">
                ostatnia zmiana: {st.updated_by}, {formatDate(st.updated_at)}
              </Text>
            )}
          </Group>

          </Stack>
        </Tabs.Panel>

        <Tabs.Panel value="history" pt="md">
          <Card withBorder>
            <Title order={4} mb="xs">
              Historia kopii
            </Title>
            {st.runs.length === 0 ? (
              <Text size="sm" c="dimmed">
                Brak kopii.
              </Text>
            ) : (
              <Table.ScrollContainer minWidth={800}>
                <Table fz="sm" verticalSpacing={4}>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Czas</Table.Th>
                      <Table.Th>Rodzaj</Table.Th>
                      <Table.Th>Wynik</Table.Th>
                      <Table.Th>Rozmiar</Table.Th>
                      <Table.Th>Wysyłka</Table.Th>
                      <Table.Th>Szczegóły</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {st.runs.map((r) => (
                      <Table.Tr key={r.id}>
                        <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(r.started_at)}</Table.Td>
                        <Table.Td>{r.kind === "manual" ? "na żądanie" : "harmonogram"}</Table.Td>
                        <Table.Td>
                          <Badge size="sm" color={runStatus[r.status].color}>
                            {runStatus[r.status].label}
                          </Badge>
                        </Table.Td>
                        <Table.Td>{r.size_bytes ? formatBytes(r.size_bytes) : "—"}</Table.Td>
                        <Table.Td>{r.remote === "ok" ? "tak" : r.remote === "error" ? <Text c="red" size="sm">błąd</Text> : "—"}</Table.Td>
                        <Table.Td>
                          <Text size="xs" style={{ wordBreak: "break-word" }}>
                            {r.message}
                          </Text>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            )}
            <Text size="xs" c="dimmed" mt="xs">
              Odtworzenie na czystym serwerze: <Code>./restore.sh &lt;kopia&gt; [katalog z paczkami archiwum]</Code> i hasło kopii.
            </Text>
          </Card>
        </Tabs.Panel>

        <Tabs.Panel value="restore" pt="md">
          <RestorePanel view={view} ask={ask} />
        </Tabs.Panel>
      </Tabs>

      <Modal opened={confirm} onClose={() => setConfirm(false)} title="Zapis ustawień kopii" centered>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <Stack gap="sm">
            <Text size="sm">Ustawienia kopii decydują, gdzie trafiają dane całego systemu – potwierdź zmianę swoim hasłem.</Text>
            <PasswordInput
              label="Twoje hasło"
              required
              autoFocus
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
            />
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setConfirm(false)}>
                Wróć
              </Button>
              <Button type="submit" loading={busy}>
                Zapisz
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Stack>
  );
}
