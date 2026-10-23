// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  Card,
  Code,
  CopyButton,
  Group,
  Modal,
  NumberInput,
  PasswordInput,
  Stack,
  Table,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconKey, IconShieldCheck } from "@tabler/icons-react";
import {
  agentsApi,
  ago,
  formatDate,
  tamperKinds,
  type AgentStatusDoc,
  type AgentView,
  type UninstallToken,
} from "../api";
import { useTranslation } from "react-i18next";

// Kolory stanów; nazwy i opisy – agents: protection.<stan>, token.<stan>.
const protectionColors: Record<string, string> = { protected: "green", open: "red", other: "red", error: "red", off: "gray", unknown: "gray" };
const tokenColors: Record<string, string> = { active: "green", used: "blue", revoked: "gray", expired: "gray" };

export function AgentProtection({ agent, status, admin }: { agent: AgentView; status: AgentStatusDoc; admin: boolean }) {
  const { t } = useTranslation("agents");
  const [tokens, setTokens] = useState<UninstallToken[]>([]);
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [hours, setHours] = useState<number | string>(24);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState<{ token: string; item: UninstallToken } | null>(null);

  const load = useCallback(() => {
    if (!admin) return;
    agentsApi
      .uninstallTokens(agent.id)
      .then((r) => setTokens(r.tokens))
      .catch(() => setTokens([]));
  }, [admin, agent.id]);
  useEffect(load, [load]);

  const create = async () => {
    setBusy(true);
    try {
      const r = await agentsApi.createUninstallToken(agent.id, { reason, hours: Number(hours) || 24, password });
      setIssued(r);
      setPassword("");
      setReason("");
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (tok: UninstallToken) => {
    if (!window.confirm(t("protection.revokeConfirm", { id: tok.token_id }))) return;
    try {
      await agentsApi.revokeUninstallToken(agent.id, tok.id);
      load();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    }
  };

  const close = () => {
    setOpen(false);
    setIssued(null);
    setPassword("");
  };

  const pk = (agent.protection ?? "unknown") in protectionColors ? (agent.protection ?? "unknown") : "unknown";
  const state = { label: t(`protection.${pk}.label`), color: protectionColors[pk], hint: t(`protection.${pk}.hint`) };
  const events = [...(status.protection?.events ?? [])].reverse();
  return (
    <Card withBorder>
      <Group justify="space-between" mb="sm">
        <Group gap="xs">
          <IconShieldCheck size={20} />
          <Title order={4}>{t("protection.title")}</Title>
          <Badge color={state.color} variant="light">
            {state.label}
          </Badge>
        </Group>
        {admin && (
          <Button size="xs" variant="light" leftSection={<IconKey size={14} />} onClick={() => setOpen(true)}>
            {t("protection.token")}
          </Button>
        )}
      </Group>
      <Text size="sm" c="dimmed">
        {state.hint}
        {agent.protection_error ? ` ${agent.protection_error}` : ""}
        {status.protection?.enabled ? ` ${t("protection.known", { n: status.protection.tokens })}` : ""}
      </Text>

      {events.length > 0 && (
        <Table.ScrollContainer minWidth={600} mt="sm">
          <Table verticalSpacing={4}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("protection.when")}</Table.Th>
                <Table.Th>{t("protection.event")}</Table.Th>
                <Table.Th>{t("protection.account")}</Table.Th>
                <Table.Th>{t("protection.details")}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {events.map((e) => {
                const k = tamperKinds[e.kind] ?? { title: e.kind, level: "" };
                return (
                  <Table.Tr key={e.id}>
                    <Table.Td>
                      <Text size="sm">{formatDate(e.at)}</Text>
                      <Text size="xs" c="dimmed">
                        {ago(e.at)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Badge color={k.level === "high" ? "red" : k.level ? "orange" : "gray"} variant="light">
                        {k.title}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{e.user || "—"}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">
                        {e.detail || ""}
                        {e.token_id ? ` token ${e.token_id}` : ""}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}

      {admin && tokens.length > 0 && (
        <Table.ScrollContainer minWidth={600} mt="sm">
          <Table verticalSpacing={4}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Token</Table.Th>
                <Table.Th>{t("col.state")}</Table.Th>
                <Table.Th>{t("protection.createdBy")}</Table.Th>
                <Table.Th>{t("protection.reason")}</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {tokens.map((tok) => (
                <Table.Tr key={tok.id}>
                  <Table.Td>
                    <Text size="sm" ff="monospace">
                      {tok.token_id}
                    </Text>
                    <Text size="xs" c="dimmed">
                      {t("protection.validUntil", { date: formatDate(tok.expires_at) })}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Badge color={tokenColors[tok.state]} variant="light">
                      {t(`token.${tok.state}`, { defaultValue: tok.state })}
                    </Badge>
                    {tok.used_at && (
                      <Text size="xs" c="dimmed">
                        {tok.used_action === "uninstall_token"
                          ? t("protection.usedUninstall")
                          : tok.used_action === "upgrade"
                            ? t("protection.usedUpgrade")
                            : t("protection.usedStop")}{" "}
                        {formatDate(tok.used_at)}
                        {tok.used_by ? ` (${tok.used_by})` : ""}
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{tok.created_by}</Text>
                    <Text size="xs" c="dimmed">
                      {formatDate(tok.created_at)}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{tok.reason}</Text>
                  </Table.Td>
                  <Table.Td>
                    {tok.state === "active" && (
                      <Button size="compact-xs" variant="subtle" color="red" onClick={() => void revoke(tok)}>
                        {t("revoke")}
                      </Button>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}

      <Modal opened={open} onClose={close} title={t("protection.modalTitle", { host: agent.hostname || agent.id })} size="lg">
        {issued ? (
          <Stack>
            <Alert color="yellow" title={t("protection.onlyNow")}>
              {t("protection.onlyNowText", { date: formatDate(issued.item.expires_at) })}
            </Alert>
            <Group>
              <Code fz="lg" fw={700}>
                {issued.token}
              </Code>
              <CopyButton value={issued.token}>
                {({ copied, copy }) => (
                  <Button size="xs" variant="light" onClick={copy}>
                    {copied ? t("copied") : t("copy")}
                  </Button>
                )}
              </CopyButton>
            </Group>
            <Text size="sm">{t("protection.onComputer")}</Text>
            <Code block>
              {`vardr-agent stop -token ${issued.token}        # ${t("protection.cmdStop")}
vardr-agent uninstall -token ${issued.token}   # ${t("protection.cmdUninstall")}
msiexec /x vardr-agent.msi /qn UNINSTALL_TOKEN=${issued.token}`}
            </Code>
            <Text size="xs" c="dimmed">
              {t("protection.refreshNote")}
            </Text>
            <Button onClick={close}>{t("close")}</Button>
          </Stack>
        ) : (
          <Stack>
            <Text size="sm">
              {t("protection.intro")}
            </Text>
            <TextInput
              label={t("protection.reason")}
              placeholder={t("protection.reasonPlaceholder")}
              value={reason}
              onChange={(e) => setReason(e.currentTarget.value)}
              required
            />
            <NumberInput label={t("protection.hours")} min={1} max={168} value={hours} onChange={setHours} w={200} />
            <PasswordInput
              label={t("yourPassword")}
              description={t("protection.passwordHint")}
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
              required
            />
            <Button loading={busy} disabled={reason.trim().length < 3 || !password} onClick={() => void create()}>
              {t("protection.generate")}
            </Button>
          </Stack>
        )}
      </Modal>
    </Card>
  );
}
