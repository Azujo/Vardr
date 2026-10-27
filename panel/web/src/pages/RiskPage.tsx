// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Anchor,
  Badge,
  Button,
  Card,
  Group,
  Modal,
  MultiSelect,
  NumberInput,
  SegmentedControl,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  TagsInput,
  Text,
  Title,
  Tooltip,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconAdjustments, IconArrowUpRight } from "@tabler/icons-react";
import { Link, useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import {
  formatDate,
  formatNumber,
  groupsApi,
  levelLabels,
  riskApi,
  type AgentGroup,
  type AlertLevel,
  type RiskConfig,
  type RiskLevel,
  type RiskScore,
  type RiskType,
} from "../api";
import { useAuth } from "../auth";
import { RiskNote, riskLevelColors, riskLevelLabel } from "../risk";
import { ReauthPassword } from "../sso";

const levels: RiskLevel[] = ["critical", "high", "medium", "low"];
const alertLevels: AlertLevel[] = ["informational", "low", "medium", "high", "critical"];

function errMsg(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

// Szczegóły wyniku: alerty, które się na niego złożyły (największe wkłady).
function ScoreDetail({ score, onClose }: { score: RiskScore | null; onClose: () => void }) {
  const { t } = useTranslation("risk");
  return (
    <Modal opened={score !== null} onClose={onClose} title={score?.display} centered size="xl">
      {score && (
        <Stack>
          <Group gap="xs">
            <Badge color={riskLevelColors[score.level]} size="lg">
              {riskLevelLabel(score.level)}
            </Badge>
            <Text fw={600}>{t("points", { score: formatNumber(score.score) })}</Text>
            <Text c="dimmed" size="sm">
              {t("detail.summary", { alerts: score.alerts, since: formatDate(score.level_since) })}
            </Text>
            {score.elevated && (
              <Badge variant="light" color="grape">
                {score.type === "user" ? t("privileged") : t("criticalHost")}
              </Badge>
            )}
          </Group>
          <Text size="sm" c="dimmed">
            {t("detail.intro")}
          </Text>
          <Table striped verticalSpacing={4} fz="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("detail.rule")}</Table.Th>
                <Table.Th>{t("detail.level")}</Table.Th>
                <Table.Th>{t("detail.lastSeen")}</Table.Th>
                <Table.Th ta="right">{t("detail.points")}</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {score.top.map((c) => (
                <Table.Tr key={c.alert_id}>
                  <Table.Td>{c.rule_title || c.rule_id}</Table.Td>
                  <Table.Td>
                    <Badge size="sm" variant="light" color={levelLabels[c.level]?.color}>
                      {levelLabels[c.level]?.label ?? c.level}
                    </Badge>
                  </Table.Td>
                  <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDate(c.last_seen)}</Table.Td>
                  <Table.Td ta="right">{formatNumber(c.points)}</Table.Td>
                  <Table.Td>
                    <Anchor component={Link} to={`/alerts/${c.alert_id}`} size="sm">
                      <IconArrowUpRight size={14} /> {t("detail.open")}
                    </Anchor>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
          <Button
            component={Link}
            to={`/alerts?status=all&${score.type === "host" ? "host" : "user"}=${encodeURIComponent(score.display)}`}
            variant="light"
          >
            {t("detail.allAlerts")}
          </Button>
        </Stack>
      )}
    </Modal>
  );
}

// Ustawienia scoringu (zmiana – z hasłem).
function Settings({ opened, onClose, onSaved }: { opened: boolean; onClose: () => void; onSaved: () => void }) {
  const { t } = useTranslation("risk");
  const [cfg, setCfg] = useState<RiskConfig | null>(null);
  const [def, setDef] = useState<RiskConfig | null>(null);
  const [groups, setGroups] = useState<AgentGroup[]>([]);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!opened) return;
    setPassword("");
    riskApi
      .config()
      .then((r) => {
        setCfg(r.config);
        setDef(r.default);
      })
      .catch((e) => notifications.show({ color: "red", message: errMsg(e) }));
    groupsApi
      .list()
      .then((r) => setGroups(r.groups))
      .catch(() => setGroups([]));
  }, [opened]);
  const save = async () => {
    if (!cfg) return;
    setBusy(true);
    try {
      await riskApi.setConfig(cfg, password);
      notifications.show({ color: "green", message: t("settings.saved") });
      onSaved();
      onClose();
    } catch (e) {
      notifications.show({ color: "red", message: errMsg(e) });
    } finally {
      setBusy(false);
    }
  };
  const num = (v: string | number, fallback: number) => (typeof v === "number" ? v : fallback);
  return (
    <Modal opened={opened} onClose={onClose} title={t("settings.title")} centered size="lg">
      {cfg && (
        <Stack>
          <Switch label={t("settings.enabled")} description={t("settings.enabledHelp")} checked={cfg.enabled} onChange={(e) => setCfg({ ...cfg, enabled: e.currentTarget.checked })} />
          <Text fw={600} size="sm">
            {t("settings.points")}
          </Text>
          <SimpleGrid cols={{ base: 2, sm: 5 }}>
            {alertLevels.map((l) => (
              <NumberInput
                key={l}
                label={levelLabels[l]?.label ?? l}
                min={0}
                max={1000}
                value={cfg.points[l] ?? 0}
                onChange={(v) => setCfg({ ...cfg, points: { ...cfg.points, [l]: num(v, 0) } })}
              />
            ))}
          </SimpleGrid>
          <Group grow>
            <NumberInput
              label={t("settings.halfLife")}
              description={t("settings.halfLifeHelp")}
              min={1}
              max={365}
              value={cfg.half_life_days}
              onChange={(v) => setCfg({ ...cfg, half_life_days: num(v, 14) })}
            />
            <NumberInput
              label={t("settings.multiplier")}
              description={t("settings.multiplierHelp")}
              min={1}
              max={10}
              step={0.5}
              decimalScale={1}
              value={cfg.multiplier}
              onChange={(v) => setCfg({ ...cfg, multiplier: num(v, 2) })}
            />
          </Group>
          <Text fw={600} size="sm">
            {t("settings.thresholds")}
          </Text>
          <SimpleGrid cols={3}>
            {(["medium", "high", "critical"] as RiskLevel[]).map((l) => (
              <NumberInput
                key={l}
                label={riskLevelLabel(l)}
                min={1}
                value={cfg.thresholds[l] ?? 0}
                onChange={(v) => setCfg({ ...cfg, thresholds: { ...cfg.thresholds, [l]: num(v, 0) } })}
              />
            ))}
          </SimpleGrid>
          <TagsInput
            label={t("settings.privileged")}
            description={t("settings.privilegedHelp")}
            placeholder="*-adm, administrator, adm.*@firma.pl"
            value={cfg.privileged_users ?? []}
            onChange={(v) => setCfg({ ...cfg, privileged_users: v })}
          />
          <MultiSelect
            label={t("settings.criticalGroups")}
            description={t("settings.criticalGroupsHelp")}
            data={groups.map((g) => ({ value: String(g.id), label: g.name }))}
            value={(cfg.critical_groups ?? []).map(String)}
            onChange={(v) => setCfg({ ...cfg, critical_groups: v.map(Number) })}
          />
          <Switch
            label={t("settings.alertAtCritical")}
            description={t("settings.alertAtCriticalHelp")}
            checked={cfg.alert_at_critical}
            onChange={(e) => setCfg({ ...cfg, alert_at_critical: e.currentTarget.checked })}
          />
          <Group justify="space-between">
            {def && (
              <Button variant="subtle" onClick={() => setCfg({ ...def, privileged_users: cfg.privileged_users, critical_groups: cfg.critical_groups })}>
                {t("settings.defaults")}
              </Button>
            )}
          </Group>
          <ReauthPassword label={t("settings.password")} value={password} onChange={setPassword} />
          <Button loading={busy} disabled={!password} onClick={() => void save()}>
            {t("settings.save")}
          </Button>
        </Stack>
      )}
    </Modal>
  );
}

// Ryzyko osób i komputerów: ranking z wynikami liczonymi przez detektor.
export default function RiskPage() {
  const { t } = useTranslation("risk");
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const type = (params.get("type") === "host" ? "host" : "user") as RiskType;
  const level = (params.get("level") ?? "") as RiskLevel | "";
  const [scores, setScores] = useState<RiskScore[]>([]);
  const [counts, setCounts] = useState<Record<RiskType, Partial<Record<RiskLevel, number>>>>({ user: {}, host: {} });
  const [enabled, setEnabled] = useState(true);
  const [error, setError] = useState("");
  const [detail, setDetail] = useState<RiskScore | null>(null);
  const [settings, setSettings] = useState(false);

  const load = useCallback(() => {
    riskApi
      .list(type, level)
      .then((r) => {
        setScores(r.scores);
        setCounts(r.counts);
        setEnabled(r.enabled);
        setError("");
        const want = params.get("entity");
        if (want) {
          const s = r.scores.find((x) => x.entity === want.toLowerCase());
          if (s) setDetail(s);
        }
      })
      .catch((e) => setError(errMsg(e)));
    // params.get("entity") – tylko przy wejściu z odznaki
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [type, level]);
  useEffect(() => {
    load();
    const i = setInterval(load, 60000);
    return () => clearInterval(i);
  }, [load]);

  const set = (k: string, v: string) => {
    const p = new URLSearchParams(params);
    if (v) p.set(k, v);
    else p.delete(k);
    p.delete("entity");
    setParams(p, { replace: true });
  };

  return (
    <Stack>
      <Group justify="space-between" align="flex-start">
        <div>
          <Title order={2}>{t("title")}</Title>
          <Text c="dimmed" size="sm" maw={900}>
            {t("intro")}
          </Text>
        </div>
        {can("risk", "write") && (
          <Button variant="light" leftSection={<IconAdjustments size={18} />} onClick={() => setSettings(true)}>
            {t("settings.title")}
          </Button>
        )}
      </Group>
      {error && <Alert color="red">{error}</Alert>}
      {!enabled && <Alert color="gray">{t("disabled")}</Alert>}

      <SimpleGrid cols={{ base: 2, md: 4 }}>
        {levels.map((l) => (
          <Card
            key={l}
            withBorder
            padding="sm"
            style={{ cursor: "pointer", borderColor: level === l ? `var(--mantine-color-${riskLevelColors[l]}-6)` : undefined }}
            onClick={() => set("level", level === l ? "" : l)}
          >
            <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
              {riskLevelLabel(l)}
            </Text>
            <Group gap="xs" align="baseline">
              <Text fw={700} size="xl" c={l === "low" ? undefined : riskLevelColors[l]}>
                {formatNumber(counts[type]?.[l] ?? 0)}
              </Text>
              <Text size="xs" c="dimmed">
                {type === "user" ? t("people") : t("hosts")}
              </Text>
            </Group>
          </Card>
        ))}
      </SimpleGrid>

      <Group>
        <SegmentedControl
          value={type}
          onChange={(v) => set("type", v === "user" ? "" : v)}
          data={[
            { value: "user", label: t("typeUser") },
            { value: "host", label: t("typeHost") },
          ]}
        />
        <Select
          w={200}
          placeholder={t("allLevels")}
          clearable
          value={level || null}
          onChange={(v) => set("level", v ?? "")}
          data={levels.map((l) => ({ value: l, label: t("fromLevel", { level: riskLevelLabel(l) }) }))}
        />
      </Group>

      <Table.ScrollContainer minWidth={760}>
        <Table striped highlightOnHover verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{type === "user" ? t("col.person") : t("col.host")}</Table.Th>
              <Table.Th>{t("col.level")}</Table.Th>
              <Table.Th ta="right">{t("col.score")}</Table.Th>
              <Table.Th ta="right">{t("col.alerts")}</Table.Th>
              <Table.Th>{t("col.lastAlert")}</Table.Th>
              <Table.Th>{t("col.since")}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {scores.length === 0 && (
              <Table.Tr>
                <Table.Td colSpan={6}>
                  <Text c="dimmed" size="sm">
                    {t("empty")}
                  </Text>
                </Table.Td>
              </Table.Tr>
            )}
            {scores.map((s) => (
              <Table.Tr key={s.entity} style={{ cursor: "pointer" }} onClick={() => setDetail(s)}>
                <Table.Td>
                  <Group gap={6}>
                    <Text fw={500}>{s.display}</Text>
                    {s.elevated && (
                      <Tooltip label={s.type === "user" ? t("privilegedTip") : t("criticalHostTip")}>
                        <Badge size="xs" variant="light" color="grape">
                          {s.type === "user" ? t("privileged") : t("criticalHost")}
                        </Badge>
                      </Tooltip>
                    )}
                  </Group>
                </Table.Td>
                <Table.Td>
                  <Badge color={riskLevelColors[s.level]} variant={s.level === "critical" ? "filled" : "light"}>
                    {riskLevelLabel(s.level)}
                  </Badge>
                </Table.Td>
                <Table.Td ta="right" fw={600}>
                  {formatNumber(s.score)}
                </Table.Td>
                <Table.Td ta="right">{formatNumber(s.alerts)}</Table.Td>
                <Table.Td>{formatDate(s.last_alert_at)}</Table.Td>
                <Table.Td>{formatDate(s.level_since)}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      <RiskNote />

      <ScoreDetail score={detail} onClose={() => setDetail(null)} />
      <Settings opened={settings} onClose={() => setSettings(false)} onSaved={load} />
    </Stack>
  );
}
