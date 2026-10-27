// SPDX-License-Identifier: AGPL-3.0-or-later

// Asystent AI w panelu (wersja 1.5): panel boczny z rozmową, „Analiza AI”
// przy alercie. Odpowiedzi to tekst modelu – renderowany bez HTML-a,
// z linkami tylko do alertów i wyszukiwarki zdarzeń panelu.

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import {
  ActionIcon,
  Alert,
  Anchor,
  Badge,
  Button,
  Card,
  Code,
  Drawer,
  Group,
  List,
  Loader,
  Paper,
  ScrollArea,
  SegmentedControl,
  Stack,
  Text,
  Textarea,
  Title,
  Tooltip,
} from "@mantine/core";
import { IconAlertTriangle, IconPlayerStop, IconRefresh, IconSend, IconSparkles, IconTool, IconTrash, IconX } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import i18n from "./i18n";
import { alertAnalysesApi, askAssistant, formatDate, type AlertAnalysis, type AssistantEvent, type ChatTurn } from "./api";
import { useAuth } from "./auth";

// ---- Markdown (podzbiór: nagłówki, listy, pogrubienie, kod, odwołania) ----

const inlineRe = /(\*\*[^*\n]+\*\*|`[^`\n]+`|\[alert:\d+\]|\[event:[^\]\n]+\]|\[query:[^\]\n]+\])/g;

function Inline({ text }: { text: string }) {
  const parts = text.split(inlineRe);
  return (
    <>
      {parts.map((p, i) => {
        if (i % 2 === 0) return p;
        if (p.startsWith("**")) return <b key={i}>{p.slice(2, -2)}</b>;
        if (p.startsWith("`")) return <Code key={i}>{p.slice(1, -1)}</Code>;
        if (p.startsWith("[alert:")) {
          const id = p.slice(7, -1);
          return (
            <Anchor key={i} component={Link} to={`/alerts/${id}`}>
              #{id}
            </Anchor>
          );
        }
        if (p.startsWith("[query:")) {
          const q = p.slice(7, -1).trim();
          return (
            <Anchor key={i} component={Link} to={`/events?q=${encodeURIComponent(q)}&range=24h`} title={i18n.t("ai:assistant.runQuery")}>
              <Code>{q}</Code>
            </Anchor>
          );
        }
        return (
          <Code key={i} c="dimmed">
            {p.slice(7, -1)}
          </Code>
        );
      })}
    </>
  );
}

export function Markdown({ text }: { text: string }) {
  const out: ReactNode[] = [];
  const lines = text.replace(/\r/g, "").split("\n");
  let list: { ordered: boolean; items: string[] } | null = null;
  let para: string[] = [];
  const flushPara = () => {
    if (para.length) {
      out.push(
        <Text key={out.length} size="sm">
          <Inline text={para.join(" ")} />
        </Text>,
      );
      para = [];
    }
  };
  const flushList = () => {
    if (list) {
      const l = list;
      out.push(
        <List key={out.length} size="sm" type={l.ordered ? "ordered" : "unordered"} spacing={2} withPadding>
          {l.items.map((it, i) => (
            <List.Item key={i}>
              <Inline text={it} />
            </List.Item>
          ))}
        </List>,
      );
      list = null;
    }
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith("```")) {
      flushPara();
      flushList();
      const code: string[] = [];
      for (i++; i < lines.length && !lines[i].trim().startsWith("```"); i++) code.push(lines[i]);
      out.push(
        <Code key={out.length} block>
          {code.join("\n")}
        </Code>,
      );
      continue;
    }
    const h = /^(#{1,4})\s+(.*)$/.exec(line);
    const li = /^\s*(?:[-*]|(\d+)[.)])\s+(.*)$/.exec(line);
    if (h) {
      flushPara();
      flushList();
      out.push(
        <Title key={out.length} order={h[1].length <= 2 ? 5 : 6} mt="xs">
          <Inline text={h[2]} />
        </Title>,
      );
    } else if (li) {
      flushPara();
      const ordered = li[1] !== undefined;
      if (!list || list.ordered !== ordered) {
        flushList();
        list = { ordered, items: [] };
      }
      list.items.push(li[2]);
    } else if (line.trim() === "") {
      flushPara();
      flushList();
    } else {
      flushList();
      para.push(line.trim());
    }
  }
  flushPara();
  flushList();
  return <Stack gap={6}>{out}</Stack>;
}

// ---- kontekst i panel boczny ----

interface AssistantCtx {
  open: (opts?: { alertId?: number }) => void;
}

const Ctx = createContext<AssistantCtx>({ open: () => {} });

export function useAssistant() {
  return useContext(Ctx);
}

interface Turn extends ChatTurn {
  label?: string; // tekst pokazywany zamiast treści (np. „Analiza alertu #7”)
  meta?: string;
}

interface Progress {
  step: number;
  tools: { name: string; fail: boolean }[];
}

export function AssistantProvider({ children }: { children: ReactNode }) {
  const [opened, setOpened] = useState(false);
  const [alertId, setAlertId] = useState<number | undefined>();
  const [startNonce, setStartNonce] = useState(0);
  const open = useCallback((opts?: { alertId?: number }) => {
    setAlertId(opts?.alertId);
    setOpened(true);
    setStartNonce((n) => n + 1);
  }, []);
  return (
    <Ctx.Provider value={{ open }}>
      {children}
      <AssistantDrawer opened={opened} onClose={() => setOpened(false)} alertId={alertId} startNonce={startNonce} clearAlert={() => setAlertId(undefined)} />
    </Ctx.Provider>
  );
}

function AssistantDrawer({
  opened,
  onClose,
  alertId,
  startNonce,
  clearAlert,
}: {
  opened: boolean;
  onClose: () => void;
  alertId?: number;
  startNonce: number;
  clearAlert: () => void;
}) {
  const { t } = useTranslation("ai");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [error, setError] = useState("");
  const abort = useRef<AbortController | null>(null);
  const convAlert = useRef<number | undefined>(undefined);
  const viewport = useRef<HTMLDivElement>(null);

  useEffect(() => {
    viewport.current?.scrollTo({ top: viewport.current.scrollHeight, behavior: "smooth" });
  }, [turns, progress]);

  const run = useCallback(
    async (question: string, history: Turn[], forAlert?: number, label?: string) => {
      setBusy(true);
      setError("");
      setProgress({ step: 0, tools: [] });
      const userTurn: Turn = { role: "user", content: question || label || "", label };
      setTurns([...history, userTurn]);
      const ac = new AbortController();
      abort.current = ac;
      let answer = "";
      let meta = "";
      try {
        await askAssistant(
          {
            alert_id: history.length === 0 ? forAlert : undefined,
            question,
            history: history.map(({ role, content }) => ({ role, content })),
            lang: (i18n.resolvedLanguage ?? "pl").slice(0, 2),
          },
          (name: string, e: AssistantEvent) => {
            if (name === "step") setProgress((p) => ({ step: e.step ?? 0, tools: p?.tools ?? [] }));
            else if (name === "tool") setProgress((p) => ({ step: p?.step ?? 0, tools: [...(p?.tools ?? []), { name: e.tool ?? "", fail: !!e.fail }] }));
            else if (name === "answer") answer = e.text ?? "";
            else if (name === "error") setError(e.message ?? "");
            else if (name === "done") {
              meta = t("assistant.meta", { model: e.model, s: Math.round((e.ms ?? 0) / 1000), steps: e.steps ?? 0, tokens: (e.prompt_tokens ?? 0) + (e.completion_tokens ?? 0) });
              if (e.analysis_id && e.alert_id) {
                meta += " · " + t("assistant.savedToAlert");
                window.dispatchEvent(new CustomEvent(analysisSavedEvent, { detail: e.alert_id }));
              }
            }
          },
          ac.signal,
        );
        if (answer) setTurns([...history, userTurn, { role: "assistant", content: answer, meta }]);
      } catch (e) {
        if (!ac.signal.aborted) setError(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
        setProgress(null);
        abort.current = null;
      }
    },
    [t],
  );

  // Otwarcie z alertu: nowa rozmowa i od razu analiza.
  useEffect(() => {
    if (!opened || startNonce === 0) return;
    if (alertId !== undefined && convAlert.current !== alertId) {
      abort.current?.abort();
      convAlert.current = alertId;
      void run("", [], alertId, t("assistant.analyzeAlert", { id: alertId }));
    }
  }, [startNonce]); // tylko nowe otwarcie z alertu

  const reset = () => {
    abort.current?.abort();
    convAlert.current = undefined;
    clearAlert();
    setTurns([]);
    setError("");
  };
  const send = () => {
    const q = input.trim();
    if (!q || busy) return;
    setInput("");
    void run(q, turns, convAlert.current);
  };

  return (
    <Drawer
      opened={opened}
      onClose={onClose}
      position="right"
      size="xl"
      title={
        <Group gap="xs">
          <IconSparkles size={18} />
          <Text fw={600}>{t("assistant.title")}</Text>
          {convAlert.current !== undefined && (
            <Badge variant="light" rightSection={<IconX size={10} style={{ cursor: "pointer" }} onClick={reset} />}>
              {t("assistant.alertBadge", { id: convAlert.current })}
            </Badge>
          )}
        </Group>
      }
      styles={{ body: { display: "flex", flexDirection: "column", height: "calc(100% - 60px)" } }}
    >
      <Text size="xs" c="dimmed" mb="xs">
        {t("assistant.disclaimer")}
      </Text>
      <ScrollArea style={{ flex: 1 }} viewportRef={viewport}>
        <Stack gap="sm" pr="sm">
          {turns.length === 0 && !busy && (
            <Stack gap="xs">
              <Text size="sm" c="dimmed">
                {t("assistant.empty")}
              </Text>
              {(["correlate", "today", "coverage"] as const).map((k) => (
                <Button key={k} size="xs" variant="light" color="violet" justify="flex-start" onClick={() => void run(t(`assistant.examples.${k}`), [])}>
                  {t(`assistant.examples.${k}`)}
                </Button>
              ))}
            </Stack>
          )}
          {turns.map((tu, i) =>
            tu.role === "user" ? (
              <Paper key={i} p="xs" radius="md" bg="var(--mantine-color-default-hover)" ml="xl">
                <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>
                  {tu.label ?? tu.content}
                </Text>
              </Paper>
            ) : (
              <Paper key={i} p="sm" radius="md" withBorder>
                <Badge size="xs" variant="light" color="violet" mb={6}>
                  {t("assistant.aiBadge")}
                </Badge>
                <Markdown text={tu.content} />
                {tu.meta && (
                  <Text size="xs" c="dimmed" mt={6}>
                    {tu.meta}
                  </Text>
                )}
              </Paper>
            ),
          )}
          {progress && (
            <Paper p="xs" radius="md" withBorder>
              <Group gap="xs">
                <Loader size="xs" />
                <Text size="sm">{progress.step > 0 ? t("assistant.thinking", { step: progress.step }) : t("assistant.starting")}</Text>
              </Group>
              {progress.tools.map((tl, i) => (
                <Group key={i} gap={6} mt={4}>
                  <IconTool size={14} color={tl.fail ? "var(--mantine-color-red-6)" : undefined} />
                  <Text size="xs" c={tl.fail ? "red" : "dimmed"}>
                    {tl.fail ? t("assistant.toolDenied", { tool: tl.name }) : t("assistant.toolCall", { tool: tl.name })}
                  </Text>
                </Group>
              ))}
            </Paper>
          )}
          {error && (
            <Alert color="red" icon={<IconAlertTriangle size={16} />}>
              {error}
            </Alert>
          )}
        </Stack>
      </ScrollArea>
      <Stack gap={6} mt="sm">
        <Textarea
          autosize
          minRows={2}
          maxRows={6}
          placeholder={t("assistant.placeholder")}
          value={input}
          onChange={(e) => setInput(e.currentTarget.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              send();
            }
          }}
        />
        <Group justify="space-between">
          <Button variant="subtle" size="xs" leftSection={<IconRefresh size={14} />} onClick={reset} disabled={busy && !abort.current}>
            {t("assistant.newChat")}
          </Button>
          <Group gap="xs">
            {busy && (
              <Tooltip label={t("assistant.stop")}>
                <ActionIcon variant="default" onClick={() => abort.current?.abort()} aria-label={t("assistant.stop")}>
                  <IconPlayerStop size={16} />
                </ActionIcon>
              </Tooltip>
            )}
            <Button size="xs" leftSection={<IconSend size={14} />} onClick={send} disabled={busy || !input.trim()}>
              {t("assistant.send")}
            </Button>
          </Group>
        </Group>
      </Stack>
    </Drawer>
  );
}

// ---- zapisane analizy przy alercie ----

const analysisSavedEvent = "vardr:ai-analysis-saved";

// AlertAnalyses: karta „Analiza AI” na stronie alertu – ostatnia zapisana
// analiza (wcześniejsze do wyboru); odświeża się po nowej analizie z czatu.
export function AlertAnalyses({ alertId }: { alertId: number }) {
  const { t } = useTranslation("ai");
  const { can } = useAuth();
  const { open } = useAssistant();
  const [list, setList] = useState<AlertAnalysis[]>([]);
  const [current, setCurrent] = useState<number | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    alertAnalysesApi
      .list(alertId)
      .then((r) => {
        setList(r.analyses);
        setCurrent(r.analyses[0]?.id ?? null);
        setError("");
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [alertId]);
  useEffect(() => load(), [load]);
  useEffect(() => {
    const h = (e: Event) => {
      if ((e as CustomEvent<number>).detail === alertId) load();
    };
    window.addEventListener(analysisSavedEvent, h);
    return () => window.removeEventListener(analysisSavedEvent, h);
  }, [alertId, load]);

  if (list.length === 0 && !error) return null;
  const a = list.find((x) => x.id === current) ?? list[0];
  const remove = async () => {
    if (!a) return;
    try {
      await alertAnalysesApi.remove(alertId, a.id);
      setConfirm(false);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };
  return (
    <Card withBorder style={{ borderColor: "var(--mantine-color-violet-filled)" }}>
      <Group justify="space-between" mb="xs" wrap="nowrap">
        <Group gap="xs">
          <IconSparkles size={18} color="var(--mantine-color-violet-filled)" />
          <Title order={4}>{t("assistant.analysisTitle")}</Title>
          <Badge size="xs" variant="light" color="violet">
            {t("assistant.aiBadge")}
          </Badge>
        </Group>
        <Group gap="xs" wrap="nowrap">
          {can("ai", "use") && (
            <Button size="xs" variant="subtle" color="violet" leftSection={<IconRefresh size={14} />} onClick={() => open({ alertId })}>
              {t("assistant.reanalyze")}
            </Button>
          )}
          {a && can("alerts", "write") &&
            (confirm ? (
              <Group gap={4} wrap="nowrap">
                <Button size="xs" color="red" onClick={() => void remove()}>
                  {t("assistant.deleteConfirm")}
                </Button>
                <Button size="xs" variant="default" onClick={() => setConfirm(false)}>
                  {t("assistant.cancel")}
                </Button>
              </Group>
            ) : (
              <Tooltip label={t("assistant.delete")}>
                <ActionIcon variant="subtle" color="gray" aria-label={t("assistant.delete")} onClick={() => setConfirm(true)}>
                  <IconTrash size={16} />
                </ActionIcon>
              </Tooltip>
            ))}
        </Group>
      </Group>
      {error && (
        <Alert color="red" icon={<IconAlertTriangle size={16} />} mb="xs">
          {error}
        </Alert>
      )}
      {a && (
        <Stack gap="xs">
          {list.length > 1 && (
            <SegmentedControl
              size="xs"
              value={String(a.id)}
              onChange={(v) => {
                setCurrent(Number(v));
                setConfirm(false);
              }}
              data={list.map((x, i) => ({ value: String(x.id), label: i === 0 ? t("assistant.latest") : formatDate(x.created_at) }))}
              style={{ alignSelf: "flex-start" }}
            />
          )}
          <Text size="xs" c="dimmed">
            {t("assistant.analysisMeta", { by: a.created_by, date: formatDate(a.created_at), model: a.model, s: Math.round(a.took_ms / 1000) })}
          </Text>
          <Markdown text={a.answer} />
          <Text size="xs" c="dimmed">
            {t("assistant.analysisNote")}
          </Text>
        </Stack>
      )}
    </Card>
  );
}
