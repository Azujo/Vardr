// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ReactNode } from "react";
import {
  ActionIcon,
  Anchor,
  AppShell,
  Burger,
  Group,
  Menu,
  NavLink,
  ScrollArea,
  Text,
  Tooltip,
  UnstyledButton,
  useComputedColorScheme,
  useMantineColorScheme,
} from "@mantine/core";
import { useEffect, useState } from "react";
import { useDisclosure } from "@mantine/hooks";
import {
  IconActivityHeartbeat,
  IconApi,
  IconSparkles,
  IconGridDots,
  IconGauge,
  IconAlertOctagon,
  IconAdjustments,
  IconAlertTriangle,
  IconArchive,
  IconBell,
  IconBolt,
  IconCheck,
  IconChevronDown,
  IconCloudLock,
  IconCode,
  IconDatabaseExport,
  IconDatabaseSearch,
  IconDeviceDesktop,
  IconHome,
  IconBuildingCommunity,
  IconFlame,
  IconKey,
  IconLanguage,
  IconLockAccess,
  IconShieldLock,
  IconListCheck,
  IconListDetails,
  IconLogout,
  IconMoon,
  IconShieldHalf,
  IconSun,
  IconUserCircle,
  IconUsers,
} from "@tabler/icons-react";
import { Link, useLocation } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { notifications } from "@mantine/notifications";
import { useAuth } from "./auth";
import ErrorBoundary from "./ErrorBoundary";
import UpdateBanner from "./UpdateBanner";
import { AssistantProvider, useAssistant } from "./assistant";
import { api, profileName } from "./api";
import { languages, setLanguage } from "./i18n";

// label, title i hint z kropką to klucze tłumaczeń (common: nav.*); hint bez
// kropki to nazwa własna modułu (Gjallarhorn, Mímir…) – się jej nie tłumaczy.
interface Item {
  to: string;
  label: string;
  hint?: string;
  icon: ReactNode;
  disabled?: boolean;
  perm?: [string, string]; // wymagane uprawnienie (moduł, poziom)
}

// Menu w grupach według tego, czym się zajmuje użytkownik. Etykieta mówi,
// co jest na stronie, a nazwa modułu z roadmapy (załącznik D) jest podpisem.
interface Section {
  title?: string;
  items: Item[];
}

const sections: Section[] = [
  { items: [{ to: "/", label: "nav.home", icon: <IconHome size={18} /> }] },
  {
    title: "nav.detection",
    items: [
      { to: "/alerts", label: "nav.alerts", hint: "Gjallarhorn", icon: <IconAlertTriangle size={18} />, perm: ["alerts", "read"] },
      { to: "/incidents", label: "nav.incidents", hint: "nav.incidentsHint", icon: <IconFlame size={18} />, perm: ["incidents", "read"] },
      { to: "/rules", label: "nav.rules", hint: "nav.rulesHint", icon: <IconListCheck size={18} />, perm: ["rules", "read"] },
      { to: "/attack", label: "nav.attack", hint: "nav.attackHint", icon: <IconGridDots size={18} />, perm: ["rules", "read"] },
      { to: "/risk", label: "nav.risk", hint: "nav.riskHint", icon: <IconGauge size={18} />, perm: ["risk", "read"] },
    ],
  },
  {
    title: "nav.events",
    items: [
      { to: "/events", label: "nav.search", hint: "Mímir", icon: <IconDatabaseSearch size={18} />, perm: ["events", "read"] },
      { to: "/identities", label: "nav.identities", hint: "nav.identitiesHint", icon: <IconUserCircle size={18} />, perm: ["identities", "read"] },
      { to: "/decoders", label: "nav.decoders", hint: "nav.decodersHint", icon: <IconCode size={18} />, perm: ["decoders", "read"] },
      { to: "/quarantine", label: "nav.quarantine", hint: "nav.quarantineHint", icon: <IconAlertOctagon size={18} />, perm: ["quarantine", "read"] },
    ],
  },
  {
    title: "nav.agents",
    items: [
      { to: "/agents", label: "nav.agentList", hint: "Huginn", icon: <IconDeviceDesktop size={18} />, perm: ["agents", "read"] },
      { to: "/groups", label: "nav.groups", hint: "nav.groupsHint", icon: <IconAdjustments size={18} />, perm: ["agents", "read"] },
      { to: "/deploy", label: "nav.deploy", hint: "nav.deployHint", icon: <IconBolt size={18} />, perm: ["deploy", "write"] },
    ],
  },
  {
    title: "nav.system",
    items: [
      { to: "/archive", label: "nav.archive", hint: "Urd", icon: <IconArchive size={18} />, perm: ["archive", "read"] },
      { to: "/system", label: "nav.systemState", hint: "Himinbjörg", icon: <IconActivityHeartbeat size={18} />, perm: ["system", "read"] },
    ],
  },
  {
    title: "nav.admin",
    items: [
      { to: "/admin/users", label: "nav.users", icon: <IconUsers size={18} />, perm: ["users", "read"] },
      { to: "/admin/profiles", label: "nav.profiles", hint: "nav.profilesHint", icon: <IconLockAccess size={18} />, perm: ["users", "read"] },
      { to: "/admin/ldap", label: "nav.ldap", hint: "Active Directory", icon: <IconBuildingCommunity size={18} />, perm: ["users", "read"] },
      { to: "/admin/sso", label: "nav.sso", hint: "Microsoft Entra ID", icon: <IconCloudLock size={18} />, perm: ["users", "read"] },
      { to: "/admin/api-tokens", label: "nav.apiTokens", hint: "nav.apiTokensHint", icon: <IconApi size={18} />, perm: ["users", "read"] },
      { to: "/admin/ai", label: "nav.ai", hint: "nav.aiHint", icon: <IconSparkles size={18} />, perm: ["ai", "read"] },
      { to: "/admin/notifications", label: "nav.notifications", hint: "Discord, Teams, webhook", icon: <IconBell size={18} />, perm: ["notify", "read"] },
      { to: "/admin/backup", label: "nav.backup", hint: "nav.backupHint", icon: <IconDatabaseExport size={18} />, perm: ["backup", "read"] },
      { to: "/admin/audit", label: "nav.audit", icon: <IconListDetails size={18} />, perm: ["audit", "read"] },
    ],
  },
];

export default function Layout({ children }: { children: ReactNode }) {
  const [opened, { toggle, close }] = useDisclosure();
  const { t } = useTranslation();
  const { user, logout, can, profile, setUserLanguage } = useAuth();
  const { pathname } = useLocation();
  const { setColorScheme } = useMantineColorScheme();
  const scheme = useComputedColorScheme("light");
  const [version, setVersion] = useState("");
  useEffect(() => {
    api
      .session()
      .then((s) => setVersion(s.server_version ?? ""))
      .catch(() => {});
  }, []);

  const changeLanguage = async (code: string) => {
    try {
      await api.setLanguage(code);
      setUserLanguage(code);
      setLanguage(code);
    } catch (e) {
      notifications.show({ color: "red", message: t("languageSaveFailed", { message: e instanceof Error ? e.message : String(e) }) });
    }
  };

  const link = (it: Item) => (
    <NavLink
      key={it.to}
      component={Link}
      to={it.to}
      label={t(it.label)}
      description={it.hint?.includes(".") ? t(it.hint) : it.hint}
      leftSection={it.icon}
      active={it.to === "/" ? pathname === "/" : pathname.startsWith(it.to)}
      disabled={it.disabled}
      onClick={close}
    />
  );

  return (
    <AssistantProvider>
      <AppShell header={{ height: 56 }} navbar={{ width: 240, breakpoint: "sm", collapsed: { mobile: !opened } }} padding="lg">
        <AppShell.Header>
          <Group h="100%" px="md" justify="space-between" wrap="nowrap">
            <Group gap="xs" wrap="nowrap">
              <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" aria-label="Menu" />
              <IconShieldHalf size={26} color="var(--mantine-color-yellow-5)" />
              <Text fw={700} size="lg">
                Vardr
              </Text>
              <Text c="dimmed" size="sm" visibleFrom="xs">
                Hliðskjálf
              </Text>
            </Group>
            <Group gap="xs" wrap="nowrap">
              {can("ai", "use") && <AssistantButton />}
              <Tooltip label={scheme === "dark" ? t("header.light") : t("header.dark")}>
                <ActionIcon
                  variant="default"
                  size="lg"
                  aria-label={t("header.toggleScheme")}
                  onClick={() => setColorScheme(scheme === "dark" ? "light" : "dark")}
                >
                  {scheme === "dark" ? <IconSun size={18} /> : <IconMoon size={18} />}
                </ActionIcon>
              </Tooltip>
              <Menu position="bottom-end" width={220}>
                <Menu.Target>
                  <UnstyledButton aria-label={t("header.accountMenu")}>
                    <Group gap={6} wrap="nowrap">
                      <div style={{ textAlign: "right" }}>
                        <Text size="sm" fw={500}>
                          {user?.display_name || user?.username}
                        </Text>
                        <Text size="xs" c="dimmed">
                          {user && (profile ? profileName(profile.id, profile.name) : t(`enum.role.${user.role}`, { defaultValue: user.role }))}
                        </Text>
                      </div>
                      <IconChevronDown size={14} />
                    </Group>
                  </UnstyledButton>
                </Menu.Target>
                <Menu.Dropdown>
                  {user?.source !== "ldap" && user?.source !== "oidc" && (
                    <Menu.Item component={Link} to="/account/password" leftSection={<IconKey size={16} />}>
                      {t("header.changePassword")}
                    </Menu.Item>
                  )}
                  <Menu.Item component={Link} to="/account/security" leftSection={<IconShieldLock size={16} />}>
                    {t("header.security")}
                  </Menu.Item>
                  <Menu.Divider />
                  <Menu.Label>
                    <Group gap={6}>
                      <IconLanguage size={14} /> {t("header.language")}
                    </Group>
                  </Menu.Label>
                  {[["", t("header.languageAuto")], ...Object.entries(languages)].map(([code, name]) => (
                    <Menu.Item
                      key={code}
                      lang={code || undefined}
                      rightSection={(user?.language ?? "") === code ? <IconCheck size={14} /> : null}
                      onClick={() => void changeLanguage(code)}
                    >
                      {name}
                    </Menu.Item>
                  ))}
                  <Menu.Divider />
                  <Menu.Item color="red" leftSection={<IconLogout size={16} />} onClick={() => void logout()}>
                    {t("header.logout")}
                  </Menu.Item>
                </Menu.Dropdown>
              </Menu>
            </Group>
          </Group>
        </AppShell.Header>

        <AppShell.Navbar p="xs">
          <AppShell.Section grow component={ScrollArea} type="scroll">
            {sections
              .map((sec) => ({ ...sec, items: sec.items.filter((it) => !it.perm || can(it.perm[0], it.perm[1])) }))
              .filter((sec) => sec.items.length > 0)
              .map((sec, i) => (
                <div key={sec.title ?? i}>
                  {sec.title && (
                    <Text size="xs" c="dimmed" fw={600} tt="uppercase" mt="md" mb={2} px="sm">
                      {t(sec.title)}
                    </Text>
                  )}
                  {sec.items.map(link)}
                </div>
              ))}
          </AppShell.Section>
          <AppShell.Section>
            <Text size="xs" c="dimmed" ta="center" my="xs" title={t("footer.versionTitle")}>
              {version && `${t("footer.version", { version })} · `}
              {/* AGPL-3.0 §13: użytkownicy panelu przez sieć mają dostęp do kodu źródłowego. */}
              <Anchor href="https://github.com/Azujo/Vardr" target="_blank" rel="noopener noreferrer" size="xs" c="dimmed" underline="always">
                {t("footer.source")}
              </Anchor>
            </Text>
          </AppShell.Section>
        </AppShell.Navbar>

        <AppShell.Main>
          <UpdateBanner />
          <ErrorBoundary resetKey={pathname}>{children}</ErrorBoundary>
        </AppShell.Main>
      </AppShell>
    </AssistantProvider>
  );
}

function AssistantButton() {
  const { t } = useTranslation("ai");
  const { open } = useAssistant();
  return (
    <Tooltip label={t("assistant.open")}>
      <ActionIcon variant="default" size="lg" aria-label={t("assistant.open")} onClick={() => open()}>
        <IconSparkles size={18} />
      </ActionIcon>
    </Tooltip>
  );
}
