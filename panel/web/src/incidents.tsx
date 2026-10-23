// SPDX-License-Identifier: AGPL-3.0-or-later

// Wspólne dla incydentów: odliczanie terminów zgłoszeń NIS2.
import { Badge, Tooltip } from "@mantine/core";
import { useTranslation } from "react-i18next";
import i18n from "./i18n";
import { formatDate, type IncidentDeadline } from "./api";

export function fmtLeft(ms: number): string {
  const abs = Math.abs(ms);
  const d = Math.floor(abs / 86400000);
  const h = Math.floor((abs % 86400000) / 3600000);
  const m = Math.floor((abs % 3600000) / 60000);
  if (d > 0) return i18n.t("duration.days", { d, h });
  if (h > 0) return i18n.t("duration.hours", { h, m });
  return i18n.t("duration.minutes", { m });
}

// Najbliższy niewysłany termin (do listy incydentów).
export function nextDeadline(ds: IncidentDeadline[]): IncidentDeadline | undefined {
  return ds.filter((d) => !d.submitted_at).sort((a, b) => a.due.localeCompare(b.due))[0];
}

export function DeadlineBadge({ d, now }: { d: IncidentDeadline; now: number }) {
  const { t } = useTranslation("incidents");
  const label = t(`reportShort.${d.kind}`);
  if (d.submitted_at) {
    return (
      <Tooltip label={t("deadline.sentAt", { date: formatDate(d.submitted_at) })}>
        <Badge color="green" variant="light">
          {t("deadline.sent", { label })}
        </Badge>
      </Tooltip>
    );
  }
  const left = new Date(d.due).getTime() - now;
  const color = left < 0 ? "red" : left < 6 * 3600000 ? "orange" : "blue";
  return (
    <Tooltip label={t("deadline.due", { date: formatDate(d.due) })}>
      <Badge color={color} variant={left < 0 ? "filled" : "light"}>
        {t(left < 0 ? "deadline.overdue" : "deadline.left", { label, left: fmtLeft(left) })}
      </Badge>
    </Tooltip>
  );
}
