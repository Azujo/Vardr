// SPDX-License-Identifier: AGPL-3.0-or-later

// Profile uprawnień: macierz moduł → poziom (brak, odczyt, test/eksport,
// zmiana). Profile wbudowane (administrator, analityk, obserwator) są stałe –
// można je skopiować jako punkt wyjścia. Zmiany z hasłem, w audycie.
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Group,
  Modal,
  SegmentedControl,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconCopy, IconPencil, IconPlus, IconTrash } from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import i18n from "../i18n";
import { api, formatDate, permHelp, permLabel, permLevel, profileName, type PermModule, type Permissions, type Profile } from "../api";
import { useAuth } from "../auth";
import { ReauthPassword } from "../sso";

interface Draft {
  id: string;
  isNew: boolean;
  name: string;
  description: string;
  permissions: Permissions;
}

// slug: identyfikator profilu z nazwy (małe litery, cyfry, myślniki).
function slug(name: string): string {
  const map: Record<string, string> = { ą: "a", ć: "c", ę: "e", ł: "l", ń: "n", ó: "o", ś: "s", ź: "z", ż: "z" };
  return name
    .toLowerCase()
    .replace(/[ąćęłńóśźż]/g, (c) => map[c] ?? c)
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
}

function summary(p: Permissions, modules: PermModule[]): string {
  const parts = modules
    .filter((m) => p[m.key])
    .map((m) => `${permLabel(m)}: ${permLevel(m, p[m.key])}`);
  return parts.length ? parts.join(" · ") : i18n.t("admin:profiles.noAccess");
}

// Opis profilu wbudowanego w języku użytkownika.
function profileDescription(p: Profile): string {
  return p.builtin ? i18n.t(`admin:profiles.builtinDesc.${p.id}`, { defaultValue: p.description }) : p.description;
}

export default function ProfilesPage() {
  const { t } = useTranslation("admin");
  const { can } = useAuth();
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [modules, setModules] = useState<PermModule[]>([]);
  const [editable, setEditable] = useState(false);
  const [error, setError] = useState("");
  const [draft, setDraft] = useState<Draft | null>(null);
  const [del, setDel] = useState<Profile | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const canEdit = can("users", "write") && editable;

  const load = useCallback(() => {
    Promise.all([api.profiles(), api.permissions()])
      .then(([p, m]) => {
        setProfiles(p.profiles);
        setEditable(p.editable);
        setModules(m.modules);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);
  useEffect(load, [load]);

  const taken = useMemo(() => new Set(profiles.map((p) => p.id)), [profiles]);
  const openDraft = (p: Profile | null, copy = false) => {
    setPassword("");
    if (!p) {
      setDraft({ id: "", isNew: true, name: "", description: "", permissions: {} });
    } else if (copy) {
      setDraft({ id: "", isNew: true, name: t("profiles.copyName", { name: profileName(p.id, p.name) }), description: profileDescription(p), permissions: { ...p.permissions } });
    } else {
      setDraft({ id: p.id, isNew: false, name: p.name, description: p.description, permissions: { ...p.permissions } });
    }
  };
  const draftID = draft ? (draft.isNew ? slug(draft.name) : draft.id) : "";
  const idProblem = draft?.isNew && draftID.length < 2 ? t("profiles.tooShort") : draft?.isNew && taken.has(draftID) ? t("profiles.idTaken") : "";

  const save = async () => {
    if (!draft) return;
    setBusy(true);
    try {
      await api.saveProfile(draftID, { name: draft.name, description: draft.description, permissions: draft.permissions, password });
      notifications.show({ color: "green", message: t("profiles.saved", { name: draft.name }) });
      setDraft(null);
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if (!del) return;
    setBusy(true);
    try {
      await api.deleteProfile(del.id, password);
      notifications.show({ color: "green", message: t("profiles.deleted", { name: del.name }) });
      setDel(null);
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack>
      <Group justify="space-between" align="flex-end">
        <div>
          <Title order={2}>{t("profiles.title")}</Title>
          <Text c="dimmed" size="sm" maw={820}>
            {t("profiles.intro")}
          </Text>
        </div>
        {canEdit && (
          <Button leftSection={<IconPlus size={16} />} onClick={() => openDraft(null)}>
            {t("profiles.new")}
          </Button>
        )}
      </Group>
      {error && <Alert color="red">{error}</Alert>}
      <Table.ScrollContainer minWidth={900}>
        <Table striped verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t("profiles.col.profile")}</Table.Th>
              <Table.Th>{t("profiles.col.permissions")}</Table.Th>
              <Table.Th>{t("profiles.col.accounts")}</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {profiles.map((p) => (
              <Table.Tr key={p.id}>
                <Table.Td maw={260}>
                  <Group gap={6}>
                    <Text fw={500}>{profileName(p.id, p.name)}</Text>
                    {p.builtin && (
                      <Badge size="xs" variant="outline">
                        {t("profiles.builtin")}
                      </Badge>
                    )}
                    {p.admin && (
                      <Badge size="xs" color="grape">
                        {t("profiles.admin")}
                      </Badge>
                    )}
                  </Group>
                  <Text size="xs" c="dimmed">
                    {profileDescription(p)}
                  </Text>
                  {!p.builtin && p.updated_by && (
                    <Text size="xs" c="dimmed">
                      {t("profiles.changedBy", { by: p.updated_by, date: formatDate(p.updated_at) })}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td maw={520}>
                  <Text size="xs">{summary(p.permissions, modules)}</Text>
                </Table.Td>
                <Table.Td>{p.users}</Table.Td>
                <Table.Td>
                  {canEdit && (
                    <Group gap={4} wrap="nowrap">
                      {!p.builtin && (
                        <Tooltip label={t("profiles.edit")}>
                          <Button size="compact-sm" variant="subtle" onClick={() => openDraft(p)}>
                            <IconPencil size={16} />
                          </Button>
                        </Tooltip>
                      )}
                      <Tooltip label={t("profiles.copy")}>
                        <Button size="compact-sm" variant="subtle" onClick={() => openDraft(p, true)}>
                          <IconCopy size={16} />
                        </Button>
                      </Tooltip>
                      {!p.builtin && (
                        <Tooltip label={p.users > 0 ? t("profiles.hasUsers") : t("profiles.delete")}>
                          <Button
                            size="compact-sm"
                            variant="subtle"
                            color="red"
                            disabled={p.users > 0}
                            onClick={() => {
                              setPassword("");
                              setDel(p);
                            }}
                          >
                            <IconTrash size={16} />
                          </Button>
                        </Tooltip>
                      )}
                    </Group>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>

      <Modal opened={!!draft} onClose={() => setDraft(null)} title={draft?.isNew ? t("profiles.new") : t("profiles.editTitle", { name: draft?.name })} size="xl">
        {draft && (
          <Stack>
            <Group grow align="flex-start">
              <TextInput
                label={t("profiles.name")}
                required
                value={draft.name}
                onChange={(e) => setDraft({ ...draft, name: e.currentTarget.value })}
                description={t("profiles.id", { id: draft.isNew ? draftID || "—" : draft.id })}
                error={idProblem || undefined}
              />
              <TextInput
                label={t("profiles.description")}
                value={draft.description}
                onChange={(e) => setDraft({ ...draft, description: e.currentTarget.value })}
                placeholder={t("profiles.descriptionPlaceholder")}
              />
            </Group>
            <Table verticalSpacing={6}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t("profiles.col.module")}</Table.Th>
                  <Table.Th>{t("profiles.col.access")}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {modules.map((m) => (
                  <Table.Tr key={m.key}>
                    <Table.Td maw={300}>
                      <Text size="sm" fw={500}>
                        {permLabel(m)}
                      </Text>
                      {m.help && (
                        <Text size="xs" c="dimmed">
                          {permHelp(m)}
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <SegmentedControl
                        size="xs"
                        value={draft.permissions[m.key] ?? ""}
                        onChange={(v) => {
                          const next = { ...draft.permissions };
                          if (v) next[m.key] = v;
                          else delete next[m.key];
                          setDraft({ ...draft, permissions: next });
                        }}
                        data={[{ value: "", label: t("profiles.none") }, ...m.levels.map((l) => ({ value: l.key, label: permLevel(m, l.key) }))]}
                      />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
            {draft.permissions.users === "write" && (
              <Alert color="grape">
                {t("profiles.adminWarning")}
              </Alert>
            )}
            <ReauthPassword label={t("yourPassword")} value={password} onChange={setPassword} />
            <Group justify="flex-end">
              <Button loading={busy} disabled={!password || draft.name.trim().length < 2 || !!idProblem} onClick={() => void save()}>
                {t("profiles.save")}
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>

      <Modal opened={!!del} onClose={() => setDel(null)} title={t("profiles.deleteTitle", { name: del?.name ?? "" })} centered>
        {del && (
          <Stack>
            <Text size="sm">{t("profiles.deleteText")}</Text>
            <ReauthPassword label={t("yourPassword")} value={password} onChange={setPassword} autoFocus />
            <Button color="red" loading={busy} disabled={!password} onClick={() => void remove()}>
              {t("profiles.delete")}
            </Button>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
