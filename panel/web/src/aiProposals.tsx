// SPDX-License-Identifier: AGPL-3.0-or-later

// Propozycje asystenta AI w odpowiedzi (wersja 1.5.3): wyjątek reguły
// (blok json {"exception": …}) i nowa reguła Sigmy (blok yaml). Asystent nic
// nie zmienia sam – przyciski otwierają formularze, w których analityk
// sprawdza propozycję (historia, test reguły) i zapisuje ją sam: wyjątek
// z powodem i hasłem, regułę w trybie próbnym (trafienia bez alertów).

import { useState } from "react";
import { Button, Group, Modal, Stack, Text, TextInput } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconFilterOff, IconHourglass } from "@tabler/icons-react";
import { useTranslation } from "react-i18next";
import { rulesApi, type ExceptionMatch } from "./api";
import { useAuth } from "./auth";
import { ExceptionModal, type ExceptionDraft } from "./pages/RuleExceptions";
import RuleTester from "./pages/RuleTester";

export interface ExceptionProposal {
  ruleId: string;
  draft: ExceptionDraft;
}

export interface RuleProposal {
  id: string;
  title: string;
  source: string;
}

function isScalar(v: unknown): v is string | number | boolean {
  return typeof v === "string" || typeof v === "number" || typeof v === "boolean";
}

// parseProposals: bloki kodu odpowiedzi z propozycjami (błędne pomijane).
export function parseProposals(text: string): { exceptions: ExceptionProposal[]; rules: RuleProposal[] } {
  const exceptions: ExceptionProposal[] = [];
  const rules: RuleProposal[] = [];
  for (const m of text.replace(/\r/g, "").matchAll(/```([a-zA-Z]*)[^\n]*\n([\s\S]*?)```/g)) {
    const lang = m[1].toLowerCase();
    const body = m[2];
    if (lang === "json" || (lang === "" && body.trim().startsWith("{"))) {
      try {
        const x = JSON.parse(body)?.exception;
        if (!x || typeof x.rule_id !== "string" || !x.match || typeof x.match !== "object") continue;
        const match: ExceptionMatch = {};
        for (const [k, v] of Object.entries(x.match as Record<string, unknown>)) {
          if (isScalar(v)) match[k] = v;
          else if (Array.isArray(v) && v.every(isScalar)) match[k] = v;
        }
        if (Object.keys(match).length === 0) continue;
        exceptions.push({ ruleId: x.rule_id, draft: { match, reason: typeof x.reason === "string" ? x.reason : "", aiProposed: true } });
      } catch {
        // nie JSON – zwykły blok kodu
      }
    } else if ((lang === "yaml" || lang === "yml" || lang === "") && /^detection:/m.test(body) && /^logsource:/m.test(body)) {
      const id = /^id:\s*['"]?([^'"\s]+)/m.exec(body)?.[1];
      if (!id || /^correlation:/m.test(body)) continue;
      rules.push({ id, title: /^title:\s*(.+)$/m.exec(body)?.[1].trim() ?? id, source: body.trimEnd() + "\n" });
    }
  }
  return { exceptions, rules };
}

// Reguła z propozycji: test na historii i zapis w panelu w trybie próbnym.
function RuleProposalModal({ rule, onClose }: { rule: RuleProposal | null; onClose: () => void }) {
  const { t } = useTranslation("ai");
  const [source, setSource] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const close = () => {
    setSource("");
    setNote("");
    onClose();
  };
  const id = /^id:\s*['"]?([^'"\s]+)/m.exec(source || rule?.source || "")?.[1] ?? "";
  const save = async () => {
    setBusy(true);
    try {
      const r = await rulesApi.savePanelRule(id, source || rule!.source, note.trim(), true, true);
      notifications.show({ color: "green", message: r.message });
      close();
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal opened={!!rule} onClose={close} size="xl" title={t("proposals.ruleTitle", { title: rule?.title ?? "" })}>
      {rule && (
        <Stack>
          <Text size="sm" c="dimmed">
            {t("proposals.ruleHelp")}
          </Text>
          <RuleTester key={rule.id} initial={rule.source} onChange={setSource} />
          <TextInput label={t("proposals.note")} value={note} onChange={(e) => setNote(e.currentTarget.value)} />
          <Group justify="flex-end">
            <Button color="yellow" leftSection={<IconHourglass size={16} />} loading={busy} disabled={!id} onClick={() => void save()}>
              {t("proposals.saveTrial")}
            </Button>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}

// ProposalActions: przyciski pod odpowiedzią asystenta (gdy są propozycje
// i analityk może zmieniać reguły).
export function ProposalActions({ text }: { text: string }) {
  const { t } = useTranslation("ai");
  const { can } = useAuth();
  const [exc, setExc] = useState<ExceptionProposal | null>(null);
  const [rule, setRule] = useState<RuleProposal | null>(null);
  if (!can("rules", "write")) return null;
  const { exceptions, rules } = parseProposals(text);
  if (exceptions.length === 0 && rules.length === 0) return null;
  return (
    <>
      <Group gap="xs" mt="xs">
        {exceptions.map((p, i) => (
          <Button key={`e${i}`} size="compact-xs" variant="light" color="cyan" leftSection={<IconFilterOff size={14} />} onClick={() => setExc(p)}>
            {t("proposals.exception", { rule: p.ruleId })}
          </Button>
        ))}
        {rules.map((r) => (
          <Button key={r.id} size="compact-xs" variant="light" color="yellow" leftSection={<IconHourglass size={14} />} onClick={() => setRule(r)}>
            {t("proposals.rule", { title: r.title })}
          </Button>
        ))}
      </Group>
      {exc && <ExceptionModal ruleId={exc.ruleId} opened onClose={() => setExc(null)} draft={exc.draft} />}
      <RuleProposalModal rule={rule} onClose={() => setRule(null)} />
    </>
  );
}
