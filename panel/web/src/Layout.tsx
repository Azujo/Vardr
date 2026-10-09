import type { ReactNode } from "react";
import {
  ActionIcon,
  AppShell,
  Badge,
  Burger,
  Group,
  Menu,
  NavLink,
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
  IconAdjustments,
  IconAlertTriangle,
  IconArchive,
  IconBell,
  IconBolt,
  IconChevronDown,
  IconCode,
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
  IconUsers,
} from "@tabler/icons-react";
import { Link, useLocation } from "react-router-dom";
import { useAuth } from "./auth";
import { api, roleLabels } from "./api";

interface Item {
  to: string;
  label: string;
  hint?: string;
  icon: ReactNode;
  disabled?: boolean;
}

// Nazwy modułów według roadmapy (załącznik D), z opisem dla nowych osób.
const main: Item[] = [
  { to: "/", label: "Start", icon: <IconHome size={18} /> },
  { to: "/agents", label: "Huginn", hint: "agenci", icon: <IconDeviceDesktop size={18} /> },
  { to: "/groups", label: "Grupy agentów", hint: "profile i limity", icon: <IconAdjustments size={18} /> },
  { to: "/events", label: "Mímir", hint: "zdarzenia", icon: <IconDatabaseSearch size={18} /> },
  { to: "/alerts", label: "Gjallarhorn", hint: "alerty", icon: <IconAlertTriangle size={18} /> },
  { to: "/rules", label: "Reguły detekcji", hint: "Sigma", icon: <IconListCheck size={18} /> },
  { to: "/decoders", label: "Dekodery", hint: "syslog: FortiGate, MikroTik…", icon: <IconCode size={18} /> },
  { to: "/deploy", label: "Bifröst", hint: "wdrażanie agentów", icon: <IconBolt size={18} /> },
  { to: "/archive", label: "Urd", hint: "archiwum NIS2", icon: <IconArchive size={18} /> },
  { to: "/system", label: "Himinbjörg", hint: "stan systemu", icon: <IconActivityHeartbeat size={18} /> },
];

const admin: Item[] = [
  { to: "/admin/users", label: "Użytkownicy", icon: <IconUsers size={18} /> },
  { to: "/admin/audit", label: "Dziennik audytu", icon: <IconListDetails size={18} /> },
  { to: "/admin/notifications", label: "Powiadomienia", hint: "Discord, webhook", icon: <IconBell size={18} /> },
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
        {main.map(link)}
        {user?.role === "admin" && (
          <>
            <Text size="xs" c="dimmed" fw={600} tt="uppercase" mt="lg" mb={4} px="sm">
              Administracja
            </Text>
            {admin.map(link)}
          </>
        )}
        <Badge variant="light" color="gray" mt="auto" mx="sm" mb={4}>
          etap 3 – w budowie
        </Badge>
        <Text size="xs" c="dimmed" ta="center" mb="xs" title="wersja siem-api">
          {version && `wersja ${version}`}
        </Text>
      </AppShell.Navbar>

      <AppShell.Main>{children}</AppShell.Main>
    </AppShell>
  );
}
