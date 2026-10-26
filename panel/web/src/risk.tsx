// SPDX-License-Identifier: AGPL-3.0-or-later

// Ryzyko osób i komputerów (wersja 1.3): wspólne elementy – rozstrzygnięcie
// przy zamykaniu alertu i odznaka ryzyka przy osobie albo komputerze.

import { useEffect, useState } from "react";
import { Badge, Radio, Stack, Text, Tooltip } from "@mantine/core";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import i18n from "./i18n";
import { formatNumber, riskApi, type Resolution, type RiskLevel, type RiskScore, type RiskType } from "./api";
import { useAuth } from "./auth";

export const riskLevelColors: Record<RiskLevel, string> = { low: "gray", medium: "yellow", high: "orange", critical: "red" };

export const riskLevelLabel = (l: RiskLevel) => i18n.t(`risk:level.${l}`);

export const resolutionLabel = (r: Resolution) => i18n.t(`risk:resolution.${r}`);

// ResolutionPicker: rozstrzygnięcie zamykanego alertu (opcjonalne).
export function ResolutionPicker({ value, onChange }: { value: Resolution | ""; onChange: (v: Resolution | "") => void }) {
  const { t } = useTranslation("risk");
  return (
    <Radio.Group label={t("resolution.label")} description={t("resolution.help")} value={value} onChange={(v) => onChange(v as Resolution | "")}>
      <Stack gap={6} mt={6}>
        {(["true_positive", "benign", "false_positive", ""] as const).map((r) => (
          <Radio key={r || "none"} value={r} label={r ? t(`resolution.${r}`) : t("resolution.none")} description={t(`resolution.hint.${r || "none"}`)} />
        ))}
      </Stack>
    </Radio.Group>
  );
}

// RiskBadge: poziom i wynik ryzyka osoby albo komputera (link do modułu
// Ryzyko); bez uprawnienia albo bez wyniku – nic.
export function RiskBadge({ type, entity }: { type: RiskType; entity: string }) {
  const { t } = useTranslation("risk");
  const { can } = useAuth();
  const allowed = can("risk", "read");
  const [score, setScore] = useState<RiskScore | null>(null);
  useEffect(() => {
    if (!allowed || !entity) return;
    let live = true;
    riskApi
      .get(type, entity)
      .then((r) => live && setScore(r.score))
      .catch(() => live && setScore(null));
    return () => {
      live = false;
    };
  }, [allowed, type, entity]);
  if (!score || score.level === "low") return null;
  return (
    <Tooltip label={t("badgeTip", { score: formatNumber(score.score), alerts: score.alerts })}>
      <Badge
        component={Link}
        to={`/risk?type=${type}&entity=${encodeURIComponent(score.entity)}`}
        ml={6}
        size="sm"
        variant="light"
        color={riskLevelColors[score.level]}
        style={{ cursor: "pointer", verticalAlign: "middle" }}
      >
        {t("badge", { level: riskLevelLabel(score.level) })}
      </Badge>
    </Tooltip>
  );
}

// RiskNote: zastrzeżenie o profilowaniu (RODO) na stronie ryzyka.
export function RiskNote() {
  const { t } = useTranslation("risk");
  return (
    <Text size="xs" c="dimmed" maw={900}>
      {t("gdpr")}
    </Text>
  );
}
