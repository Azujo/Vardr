import type { ReactNode } from "react";
import {
  ActionIcon,
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
  IconGridDots,
  IconAlertOctagon,
  IconAdjustments,
  IconAlertTriangle,
  IconArchive,
  IconBell,
  IconBolt,
  IconChevronDown,
  IconCode,
  IconDatabaseExport,
  IconDatabaseSearch,
  IconDeviceDesktop,
  IconHome,
  IconKey,
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
import { useAuth } from "./auth";
import ErrorBoundary from "./ErrorBoundary";
import UpdateBanner from "./UpdateBanner";
import { api, roleLabels } from "./api";

interface Item {
  to: string;
  label: string;
  hint?: string;
  icon: ReactNode;
  disabled?: boolean;
}

// Menu w grupach według tego, czym się zajmuje użytkownik. Etykieta mówi,
// co jest na stronie, a nazwa modułu z roadmapy (załącznik D) jest podpisem.
interface Section {
  title?: string;
  items: Item[];
  adminOnly?: boolean;
}

const sections: Section[] = [
  { items: [{ to: "/", label: "Start", icon: <IconHome size={18} /> }] },
  {
    title: "Wykrywanie",
    items: [
      { to: "/alerts", label: "Alerty", hint: "Gjallarhorn", icon: <IconAlertTriangle size={18} /> },
      { to: "/rules", label: "Reguły detekcji", hint: "Sigma i wbudowane", icon: <IconListCheck size={18} /> },
      { to: "/attack", label: "MITRE ATT&CK", hint: "pokrycie technik", icon: <IconGridDots size={18} /> },
    ],
  },
  {
    title: "Zdarzenia",
    items: [
      { to: "/events", label: "Wyszukiwarka", hint: "Mímir", icon: <IconDatabaseSearch size={18} /> },
      { to: "/identities", label: "Tożsamości", hint: "osoby i ich konta", icon: <IconUserCircle size={18} /> },
      { to: "/decoders", label: "Dekodery", hint: "syslog i API", icon: <IconCode size={18} /> },
      { to: "/quarantine", label: "Kwarantanna", hint: "nieprzetworzone zdarzenia", icon: <IconAlertOctagon size={18} /> },
    ],
  },
  {
    title: "Agenci",
    items: [
      { to: "/agents", label: "Lista agentów", hint: "Huginn", icon: <IconDeviceDesktop size={18} /> },
      { to: "/groups", label: "Grupy agentów", hint: "profile, limity, ochrona", icon: <IconAdjustments size={18} /> },
      { to: "/deploy", label: "Wdrażanie", hint: "Bifröst – tokeny i paczki", icon: <IconBolt size={18} /> },
    ],
  },
  {
    title: "System",
    items: [
      { to: "/archive", label: "Archiwum NIS2", hint: "Urd", icon: <IconArchive size={18} /> },
      { to: "/system", label: "Stan systemu", hint: "Himinbjörg", icon: <IconActivityHeartbeat size={18} /> },
    ],
  },
  {
    title: "Administracja",
    adminOnly: true,
    items: [
      { to: "/admin/users", label: "Użytkownicy", icon: <IconUsers size={18} /> },
      { to: "/admin/notifications", label: "Powiadomienia", hint: "Discord, webhook", icon: <IconBell size={18} /> },
      { to: "/admin/backup", label: "Kopie zapasowe", hint: "harmonogram i miejsce", icon: <IconDatabaseExport size={18} /> },
      { to: "/admin/audit", label: "Dziennik audytu", icon: <IconListDetails size={18} /> },
    ],
  },
];

export default function Layout({ children }: { children: ReactNode }) {
  const [opened, { toggle, close }] = useDisclosure();
  const { user, logout } = useAuth();
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

  const link = (it: Item) => (
    <NavLink
      key={it.to}
      component={Link}
      to={it.to}
      label={it.label}
      description={it.hint}
      leftSection={it.icon}
      active={it.to === "/" ? pathname === "/" : pathname.startsWith(it.to)}
      disabled={it.disabled}
      onClick={close}
    />
  );

  return (
    <AppShell header={{ height: 56 }} navbar={{ width: 240, breakpoint: "sm", collapsed: { mobile: !opened } }} padding="lg">
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="xs" wrap="nowrap">
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" aria-label="Menu" />
            <IconShieldHalf size={26} color="var(--mantine-color-yellow-5)" />
            <Text fw={700} size="lg">
              Heimdall
            </Text>
            <Text c="dimmed" size="sm" visibleFrom="xs">
              Hliðskjálf
            </Text>
          </Group>
          <Group gap="xs" wrap="nowrap">
            <Tooltip label={scheme === "dark" ? "Tryb jasny" : "Tryb ciemny"}>
              <ActionIcon
                variant="default"
                size="lg"
                aria-label="Przełącz tryb kolorów"
                onClick={() => setColorScheme(scheme === "dark" ? "light" : "dark")}
              >
                {scheme === "dark" ? <IconSun size={18} /> : <IconMoon size={18} />}
              </ActionIcon>
            </Tooltip>
            <Menu position="bottom-end" width={220}>
              <Menu.Target>
                <UnstyledButton aria-label="Menu konta">
                  <Group gap={6} wrap="nowrap">
                    <div style={{ textAlign: "right" }}>
                      <Text size="sm" fw={500}>
                        {user?.display_name || user?.username}
                      </Text>
                      <Text size="xs" c="dimmed">
                        {user && roleLabels[user.role]}
                      </Text>
                    </div>
                    <IconChevronDown size={14} />
                  </Group>
                </UnstyledButton>
              </Menu.Target>
              <Menu.Dropdown>
                <Menu.Item component={Link} to="/account/password" leftSection={<IconKey size={16} />}>
                  Zmień hasło
                </Menu.Item>
                <Menu.Item color="red" leftSection={<IconLogout size={16} />} onClick={() => void logout()}>
                  Wyloguj
                </Menu.Item>
              </Menu.Dropdown>
            </Menu>
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="xs">
        <AppShell.Section grow component={ScrollArea} type="scroll">
          {sections
            .filter((sec) => !sec.adminOnly || user?.role === "admin")
            .map((sec, i) => (
              <div key={sec.title ?? i}>
                {sec.title && (
                  <Text size="xs" c="dimmed" fw={600} tt="uppercase" mt="md" mb={2} px="sm">
                    {sec.title}
                  </Text>
                )}
                {sec.items.map(link)}
              </div>
            ))}
        </AppShell.Section>
        <AppShell.Section>
          <Text size="xs" c="dimmed" ta="center" my="xs" title="wersja siem-api">
            {version && `wersja ${version}`}
          </Text>
        </AppShell.Section>
      </AppShell.Navbar>

      <AppShell.Main>
        <UpdateBanner />
        <ErrorBoundary resetKey={pathname}>{children}</ErrorBoundary>
      </AppShell.Main>
    </AppShell>
  );
}
