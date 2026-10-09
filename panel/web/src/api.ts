// Klient API siem-api. Sesja w ciasteczku HttpOnly (JS jej nie widzi),
// token CSRF w pamięci – dołączany do każdego żądania zmieniającego stan.

export type Role = "admin" | "analyst" | "viewer";

export interface User {
  id: number;
  username: string;
  display_name: string;
  role: Role;
  disabled: boolean;
  must_change_password: boolean;
  locked_until?: string;
  last_login_at?: string;
  created_at: string;
  updated_at: string;
}

export interface SessionInfo {
  user: User;
  csrf_token: string;
  server_version?: string;
}

export interface AuditEntry {
  id: number;
  at: string;
  user_id?: number;
  username: string;
  action: string;
  target?: string;
  ip?: string;
  details?: Record<string, unknown>;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

let csrfToken = "";
let onUnauthenticated: () => void = () => {};

export function setCsrfToken(token: string) {
  csrfToken = token;
}

// Wywoływane, gdy sesja wygaśnie w trakcie pracy (powrót do logowania).
export function setUnauthenticatedHandler(fn: () => void) {
  onUnauthenticated = fn;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;

  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new ApiError(res.status, data.error ?? "error", data.message ?? `błąd HTTP ${res.status}`);
    if (res.status === 401 && path !== "/api/v1/auth/login" && path !== "/api/v1/auth/session") onUnauthenticated();
    throw err;
  }
  return data as T;
}

export const api = {
  session: () => request<SessionInfo>("GET", "/api/v1/auth/session"),
  login: (username: string, password: string) =>
    request<SessionInfo>("POST", "/api/v1/auth/login", { username, password }),
  logout: () => request<void>("POST", "/api/v1/auth/logout"),
  changePassword: (current_password: string, new_password: string) =>
    request<SessionInfo>("POST", "/api/v1/auth/password", { current_password, new_password }),
  health: () => request<{ status: string; database: string }>("GET", "/api/v1/health"),

  users: () => request<{ users: User[] }>("GET", "/api/v1/users"),
  createUser: (u: { username: string; display_name: string; role: Role }) =>
    request<{ user: User; temp_password: string }>("POST", "/api/v1/users", u),
  updateUser: (id: number, patch: { display_name?: string; role?: Role; disabled?: boolean }) =>
    request<{ user: User }>("PATCH", `/api/v1/users/${id}`, patch),
  resetPassword: (id: number) =>
    request<{ user: User; temp_password: string }>("POST", `/api/v1/users/${id}/reset-password`),

  audit: (before?: number) =>
    request<{ entries: AuditEntry[] }>("GET", `/api/v1/audit?limit=100${before ? `&before=${before}` : ""}`),
};

export const roleLabels: Record<Role, string> = {
  admin: "Administrator",
  analyst: "Analityk",
  viewer: "Tylko odczyt",
};

export function formatDate(iso?: string): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("pl-PL", { dateStyle: "short", timeStyle: "medium" });
}

// ---- Huginn: agenci ----

export interface AgentView {
  id: string;
  hostname: string;
  os: string;
  version: string;
  remote_ip: string;
  first_seen: string;
  last_seen: string;
  started_at?: string;
  cert_not_after?: string;
  cert_days_left?: number;
  state: "online" | "offline";
  server_healthy: boolean;
  last_accepted_at?: string;
  events_accepted: number;
  events_read: number;
  events_quarantined: number;
  warnings: number;
  last_warning?: string;
  channels_ok: number;
  channels_total: number;
  sysmon?: "running" | "stopped" | "missing" | "unknown";
  sysmon_version?: string;
  sysmon_config?: string;
  sysmon_required?: boolean;
  problems: string[];
  group_id: number;
  group: string;
  config_expected: string;
  config_applied?: string;
  config_state: "applied" | "pending" | "unknown";
}

export interface AgentsSummary {
  total: number;
  online: number;
  offline: number;
  with_problems: number;
}

// Status agenta – ten sam dokument co `siem_agent status` (status.json).
export interface AgentStatusDoc {
  updated_at?: string;
  version?: string;
  pid?: number;
  started_at?: string;
  server?: { url?: string; last_accepted_at?: string; last_error?: string; last_error_at?: string; healthy?: boolean };
  channels?: { name: string; state: string; error?: string; last_record_id?: number; last_read_at?: string; last_lag_ns?: number }[];
  counters?: { read?: number; filtered?: number; accepted?: number; truncated?: number; quarantined?: number; retries?: number };
  limits?: Record<string, unknown>;
  throttle?: { eps_ns?: number; bandwidth_ns?: number };
  process?: { cpu_time_ns?: number; heap_mb?: number; sys_mb?: number; goroutines?: number; max_procs?: number };
  buffer?: {
    batches: number;
    bytes: number;
    max_bytes: number;
    on_full: string;
    oldest_at?: string;
    spooled_events: number;
    dropped_events: number;
    full: boolean;
    disabled: boolean;
    last_error?: string;
  };
  clock?: { offset_ms: number; uncertainty_ms: number; measured_at?: string; time_service?: string };
  sysmon?: { installed: boolean; service?: string; running: boolean; version?: string; config_hash?: string };
  warnings?: string[];
}

export const agentsApi = {
  list: () => request<{ agents: AgentView[]; summary: AgentsSummary; offline_after_s: number }>("GET", "/api/v1/agents"),
  get: (id: string) =>
    request<{ agent: AgentView; status: AgentStatusDoc }>("GET", `/api/v1/agents/${encodeURIComponent(id)}`),
  remove: (id: string) => request<void>("DELETE", `/api/v1/agents/${encodeURIComponent(id)}`),
};

// Czas względny po polsku: „30 s temu”, „5 min temu”, „2 h temu”.
export function ago(iso?: string, now = Date.now()): string {
  if (!iso) return "—";
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s} s temu`;
  if (s < 3600) return `${Math.floor(s / 60)} min temu`;
  if (s < 172800) return `${Math.floor(s / 3600)} h temu`;
  return `${Math.floor(s / 86400)} dni temu`;
}

export function formatNumber(n?: number): string {
  return n === undefined ? "—" : n.toLocaleString("pl-PL");
}

// ---- Bifröst: rejestracja agentów tokenem ----

export type AgentProfile = "workstation" | "server" | "dc";

export interface EnrollToken {
  id: number;
  name: string;
  profile: AgentProfile;
  max_uses: number;
  uses: number;
  expires_at: string;
  created_at: string;
  created_by: string;
  revoked_at?: string;
  group_id?: number;
}

export const enrollApi = {
  list: () =>
    request<{ tokens: EnrollToken[]; profiles: Record<AgentProfile, string>; enabled: boolean; public_server: string }>("GET", "/api/v1/enroll-tokens"),
  create: (t: { name: string; profile: AgentProfile; valid_hours: number; max_uses: number; group_id?: number }) =>
    request<{ token: EnrollToken; secret: string }>("POST", "/api/v1/enroll-tokens", t),
  revoke: (id: number) => request<{ token: EnrollToken }>("POST", `/api/v1/enroll-tokens/${id}/revoke`),
  revokeAgent: (id: string, reason: string) =>
    request<{ revoked: number }>("POST", `/api/v1/agents/${encodeURIComponent(id)}/revoke`, { reason }),

  // Paczka ZIP: token w treści żądania (nie w adresie), plik zapisywany przez przeglądarkę.
  downloadPackage: async (secret: string) => {
    const res = await fetch("/api/v1/enroll-tokens/package", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      body: JSON.stringify({ secret }),
      credentials: "same-origin",
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new ApiError(res.status, data.error ?? "error", data.message ?? `błąd HTTP ${res.status}`);
    }
    const name = /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") ?? "")?.[1] ?? "heimdall-agent.zip";
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  },
};

// ---- Mímir: zdarzenia ----

export interface EventRow {
  timestamp: string;
  event_id: string;
  agent_id: string;
  host: string;
  dataset: string;
  code: number;
  action: string;
  outcome: string;
  user: string;
  domain: string;
  ip: string;
  process: string;
  message: string;
}

export interface EventDetail extends EventRow {
  ingested: string;
  provider: string;
  command_line: string;
  fields: Record<string, string>;
  raw: string;
  truncated: boolean;
  parser_version: string;
  time_quality: string;
}

export interface SearchParams {
  q: string;
  from: string;
  to: string;
  before_ts?: string;
  before_id?: string;
  // "replay": zdarzenia odtworzone z archiwum (osobna tabela).
  source?: string;
}

function qs(p: Record<string, string | undefined>): string {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(p)) if (v) u.set(k, v);
  return u.toString();
}

export const eventsApi = {
  search: (p: SearchParams) =>
    request<{ events: EventRow[]; next?: { before_ts: string; before_id: string }; took_ms: number }>(
      "GET",
      `/api/v1/events?${qs({ ...p, limit: "100" })}`,
    ),
  histogram: (p: SearchParams) =>
    request<{ buckets: { t: string; count: number }[]; interval_s: number; total: number }>(
      "GET",
      `/api/v1/events/histogram?${qs({ q: p.q, from: p.from, to: p.to, source: p.source })}`,
    ),
  get: (id: string, ts: string, source?: string) =>
    request<{ event: EventDetail }>("GET", `/api/v1/events/${encodeURIComponent(id)}?${qs({ ts, source })}`),
  fields: () => request<{ fields: { name: string; help: string }[] }>("GET", "/api/v1/events/fields"),
};

// ---- Grupy agentów (konfiguracja z serwera) ----

export interface AgentLimits {
  priority?: "normal" | "below_normal" | "background";
  cpu_max_percent?: number;
  memory_soft_mb?: number;
  memory_hard_mb?: number;
  max_eps?: number;
  max_send_kbps?: number;
  buffer_max_mb?: number;
  buffer_on_full?: "pause" | "drop_oldest";
  require_sysmon?: boolean;
}

export interface AgentGroup {
  id: number;
  name: string;
  description: string;
  profile: AgentProfile;
  limits: AgentLimits;
  is_default: boolean;
  agents: number;
  config_version: string;
  updated_at: string;
}

export const groupsApi = {
  list: () => request<{ groups: AgentGroup[] }>("GET", "/api/v1/groups"),
  create: (g: { name: string; description: string; profile: AgentProfile; limits: AgentLimits }) =>
    request<{ group: AgentGroup }>("POST", "/api/v1/groups", g),
  update: (id: number, g: { name: string; description: string; profile: AgentProfile; limits: AgentLimits }) =>
    request<{ group: AgentGroup }>("PATCH", `/api/v1/groups/${id}`, g),
  remove: (id: number) => request<void>("DELETE", `/api/v1/groups/${id}`),
  assign: (agentId: string, groupId: number) =>
    request<{ group: AgentGroup }>("PUT", `/api/v1/agents/${encodeURIComponent(agentId)}/group`, { group_id: groupId }),
};

export const configStateLabels: Record<string, { label: string; color: string; hint: string }> = {
  applied: { label: "aktualna", color: "green", hint: "agent stosuje bieżącą konfigurację grupy" },
  pending: { label: "oczekuje", color: "yellow", hint: "agent pobierze nową konfigurację w ciągu ok. 5 minut" },
  unknown: { label: "nieznana", color: "gray", hint: "agent starszy niż 0.5.0 albo jeszcze nie pobrał konfiguracji" },
};

// ---- Urd: archiwum NIS2 ----

export type Compliance =
  | "ok"
  | "problems"
  | "archiver_down"
  | "disabled"
  | "policy_scheduled"
  | "disk_full"
  | "disk_low"
  | "stale"
  | "never_verified"
  | "not_configured";

export interface ArchiverState {
  version: string;
  retention_days: number;
  segment_max_mb: number;
  segment_max_age_s: number;
  verify_every_s: number;
  started_at: string;
  heartbeat_at: string;
  verify_requested_at?: string;
  verify_requested_by?: string;
  disk_free_bytes: number;
  disk_total_bytes: number;
  paused?: string;
  min_retention_days: number;
  max_retention_days: number;
  policy_grace_s: number;
  exclude_prefixes: string[];
}

export interface ArchiveSummary {
  manifests: number;
  manifests_total: number;
  bytes: number;
  batches: number;
  oldest_hour?: string;
  newest_hour?: string;
  open_segments: number;
  open_bytes: number;
  open_batches: number;
  last_segment_at?: string;
}

export interface ArchiveVerification {
  id: number;
  started_at: string;
  finished_at: string;
  ok: boolean;
  manifests: number;
  segments: number;
  records: number;
  bytes: number;
  problems: string[];
  full_manifests: number;
  unverified: number;
  oldest_full_check?: string;
}

export interface ArchiveManifest {
  seq: number;
  hour: string;
  sha256: string;
  prev_sha256: string;
  segments: number;
  records: number;
  bytes: number;
  created_at: string;
  expired_at?: string;
  verified_at?: string;
}

export interface ArchiveOverview {
  compliance: Compliance;
  archiver?: ArchiverState | null;
  archiver_running?: boolean;
  summary?: ArchiveSummary;
  last_verification?: ArchiveVerification | null;
  manifests?: ArchiveManifest[];
  verifications?: ArchiveVerification[];
  policy?: ArchivePolicy | null;
  scheduled_change?: PolicyChange | null;
}

export interface ArchivePolicy {
  enabled: boolean;
  retention_days: number;
  excluded_groups: number[];
  excluded_agents: string[];
  change_id?: number;
  updated_at: string;
  updated_by: string;
}

export type PolicyChangeStatus = "pending" | "scheduled" | "applied" | "rejected" | "cancelled" | "superseded";
export type Weakening = "disable" | "retention" | "groups" | "agents";

export interface PolicyChange {
  id: number;
  requested_at: string;
  requested_by: string;
  reason: string;
  enabled: boolean;
  retention_days: number;
  excluded_groups: number[];
  excluded_agents: string[];
  reauth: boolean;
  status: PolicyChangeStatus;
  weakening: Weakening[];
  effective_at?: string;
  applied_at?: string;
  cancelled_at?: string;
  cancelled_by?: string;
  error?: string;
}

export interface UnarchivedSource {
  agent_id: string;
  hostname: string;
  group: string;
  reason: "disabled" | "agent" | "group" | "group_pending" | "prefix";
  effective_at?: string;
}

export interface PolicyInfo {
  policy: ArchivePolicy | null;
  scheduled_change?: PolicyChange | null;
  bounds: { min_retention_days: number; max_retention_days: number; grace_s: number; exclude_prefixes: string[] };
  changes: PolicyChange[];
  unarchived: UnarchivedSource[];
  agents_total?: number;
}

export interface PolicyChangeRequest {
  enabled: boolean;
  retention_days: number;
  excluded_groups: number[];
  excluded_agents: string[];
  reason: string;
  password?: string;
}

export const archiveApi = {
  overview: () => request<ArchiveOverview>("GET", "/api/v1/archive"),
  verify: () => request<{ message: string }>("POST", "/api/v1/archive/verify"),
  policy: () => request<PolicyInfo>("GET", "/api/v1/archive/policy"),
  changePolicy: (p: PolicyChangeRequest) =>
    request<{ change: PolicyChange; weakening: Weakening[]; grace_s: number; message: string }>("POST", "/api/v1/archive/policy", p),
  cancelChange: (id: number) => request<{ message: string }>("POST", `/api/v1/archive/policy/changes/${id}/cancel`),
};

export const weakeningLabels: Record<Weakening, string> = {
  disable: "wyłączenie archiwizacji",
  retention: "krótsza retencja",
  groups: "wyłączenie grup agentów",
  agents: "wyłączenie agentów",
};

export const policyStatusLabels: Record<PolicyChangeStatus, { label: string; color: string }> = {
  pending: { label: "oczekuje", color: "yellow" },
  scheduled: { label: "zaplanowana", color: "orange" },
  applied: { label: "obowiązuje / obowiązywała", color: "green" },
  rejected: { label: "odrzucona", color: "red" },
  cancelled: { label: "anulowana", color: "gray" },
  superseded: { label: "zastąpiona", color: "gray" },
};

export const unarchivedReasonLabels: Record<UnarchivedSource["reason"], string> = {
  disabled: "archiwum wyłączone",
  agent: "agent wyłączony",
  group: "grupa wyłączona",
  group_pending: "grupa wyłączona – po karencji (do tego czasu archiwizowany)",
  prefix: "konfiguracja serwera",
};

export function formatDuration(s: number): string {
  if (s >= 86400 && s % 86400 === 0) return `${s / 86400} d`;
  if (s >= 3600) return `${Math.round(s / 360) / 10} h`;
  return `${Math.round(s / 60)} min`;
}

export const complianceLabels: Record<Compliance, { label: string; color: string; hint: string }> = {
  ok: { label: "zgodne", color: "green", hint: "Archiwizator działa, ostatnia weryfikacja integralności nie wykryła zmian." },
  problems: {
    label: "NIEZGODNOŚCI",
    color: "red",
    hint: "Ostatnia weryfikacja wykryła zmienione, brakujące lub obce dane w archiwum – sprawdź listę problemów.",
  },
  archiver_down: {
    label: "archiwizator nie działa",
    color: "red",
    hint: "Brak sygnału od archiwizatora od ponad 3 minut. Paczki czekają w kolejce, a po jej zapełnieniu serwer wstrzyma przyjmowanie.",
  },
  disk_full: {
    label: "archiwizacja wstrzymana – brak miejsca",
    color: "red",
    hint: "Na dysku archiwum zostało za mało miejsca. Nowe paczki czekają w kolejce; po jej zapełnieniu serwer wstrzyma przyjmowanie zdarzeń. Zwolnij lub powiększ dysk archiwum.",
  },
  disabled: {
    label: "archiwizacja WYŁĄCZONA",
    color: "red",
    hint: "Polityka archiwum wyłączyła zapis nowych paczek. Dane już zarchiwizowane zostają do końca retencji. Zmiana – zakładka Polityka.",
  },
  policy_scheduled: {
    label: "zaplanowane osłabienie polityki",
    color: "orange",
    hint: "Zlecono zmianę osłabiającą ochronę archiwum (wyłączenie, krótszą retencję albo wyłączenie źródeł). Wejdzie w życie po karencji – do tego czasu można ją anulować w zakładce Polityka.",
  },
  disk_low: { label: "mało miejsca na dysku", color: "orange", hint: "Na dysku archiwum zostało mniej niż 15% miejsca." },
  stale: { label: "weryfikacja nieaktualna", color: "orange", hint: "Weryfikacja nie przeszła w zaplanowanym czasie." },
  never_verified: { label: "czeka na weryfikację", color: "blue", hint: "Archiwizator działa; pierwsza weryfikacja ok. 2 min po starcie." },
  not_configured: { label: "nie skonfigurowane", color: "gray", hint: "Archiwizator (siem-archiver) jeszcze nie działał." },
};

export function formatBytes(n?: number): string {
  if (n === undefined) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toLocaleString("pl-PL", { maximumFractionDigits: i ? 1 : 0 })} ${units[i]}`;
}

export type ExportStatus = "pending" | "running" | "done" | "failed" | "expired";

export interface ArchiveExport {
  id: number;
  requested_at: string;
  requested_by: string;
  reason: string;
  from: string;
  to: string;
  status: ExportStatus;
  started_at?: string;
  finished_at?: string;
  error?: string;
  file_name?: string;
  bytes: number;
  sha256?: string;
  manifests: number;
  segments: number;
  records: number;
  agents: string[];
}

export const exportsApi = {
  list: () => request<{ exports: ArchiveExport[]; downloads: boolean }>("GET", "/api/v1/archive/exports"),
  create: (e: { from: string; to: string; reason: string; agents?: string[]; groups?: number[] }) =>
    request<{ export: ArchiveExport }>("POST", "/api/v1/archive/exports", e),
  downloadUrl: (id: number) => `/api/v1/archive/exports/${id}/download`,
};

export const exportStatusLabels: Record<ExportStatus, { label: string; color: string }> = {
  pending: { label: "w kolejce", color: "blue" },
  running: { label: "w przygotowaniu", color: "blue" },
  done: { label: "gotowy", color: "green" },
  failed: { label: "nieudany", color: "red" },
  expired: { label: "usunięty po terminie", color: "gray" },
};

export type ReplayStatus = "pending" | "running" | "done" | "failed";

export interface ArchiveReplay {
  id: number;
  requested_at: string;
  requested_by: string;
  reason: string;
  from: string;
  to: string;
  agents: string[];
  status: ReplayStatus;
  started_at?: string;
  finished_at?: string;
  error?: string;
  batches: number;
  skipped: number;
  bytes: number;
}

export const replaysApi = {
  list: () => request<{ replays: ArchiveReplay[] }>("GET", "/api/v1/archive/replays"),
  create: (r: { from: string; to: string; agents: string[]; reason: string }) =>
    request<{ replay: ArchiveReplay }>("POST", "/api/v1/archive/replays", r),
};

export const replayStatusLabels: Record<ReplayStatus, { label: string; color: string }> = {
  pending: { label: "w kolejce", color: "blue" },
  running: { label: "w toku", color: "blue" },
  done: { label: "zakończone", color: "green" },
  failed: { label: "nieudane", color: "red" },
};

// ---- Powiadomienia (kanały: Discord, webhook) ----

export type NotifyEvent = "alert" | "health" | "anchor";

export interface NotifyChannel {
  id: number;
  name: string;
  kind: "discord" | "webhook";
  url_hint: string;
  events: NotifyEvent[];
  enabled: boolean;
  created_at: string;
  created_by: string;
  updated_at: string;
  last_ok_at?: string;
  last_error?: string;
  last_error_at?: string;
}

export interface NotifyLogEntry {
  id: number;
  at: string;
  channel: string;
  event: string;
  title: string;
  ok: boolean;
  error?: string;
  anchor_seq?: number;
  anchor_sha256?: string;
  anchor_match?: boolean;
}

export interface ChannelRequest {
  name: string;
  kind?: "discord" | "webhook";
  url?: string;
  events: NotifyEvent[];
  enabled?: boolean;
  password?: string;
}

export const notifyApi = {
  list: () =>
    request<{ channels: NotifyChannel[]; log: NotifyLogEntry[]; anchor_hour: number; relay_configured: boolean }>(
      "GET",
      "/api/v1/notify/channels",
    ),
  create: (c: ChannelRequest) => request<{ channel: NotifyChannel }>("POST", "/api/v1/notify/channels", c),
  update: (id: number, c: ChannelRequest) => request<{ channel: NotifyChannel }>("PATCH", `/api/v1/notify/channels/${id}`, c),
  remove: (id: number, password: string) => request<void>("POST", `/api/v1/notify/channels/${id}/delete`, { password }),
  test: (id: number) => request<{ message: string }>("POST", `/api/v1/notify/channels/${id}/test`),
  sendAnchor: () => request<{ message: string }>("POST", "/api/v1/notify/anchor"),
};

export const notifyEventLabels: Record<string, string> = {
  alert: "alerty detekcji (Gjallarhorn)",
  health: "alerty zdrowia systemu",
  anchor: "kotwica archiwum (codziennie)",
  test: "test",
};

// ---- Gjallarhorn: alerty i reguły ----

export type AlertLevel = "informational" | "low" | "medium" | "high" | "critical";
export type AlertStatus = "open" | "acknowledged" | "closed";

export interface Alert {
  id: number;
  rule_id: string;
  rule_title: string;
  level: AlertLevel;
  engine: string;
  group_key: string;
  group_fields: Record<string, string>;
  status: AlertStatus;
  hits: number;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  agent_id: string;
  host_name: string;
  user_name: string;
  source_ip: string;
  first_event_id: string;
  summary: string;
  closed_at?: string;
  closed_by?: string;
  close_reason?: string;
}

export interface RuleInfo {
  id: string;
  title: string;
  level: AlertLevel;
  description: string;
  tags: string[];
  file: string;
  source?: string;
  mode: string;
  enabled: boolean;
  group_by: string[];
  suppress_s: number;
  instructions: string;
  loaded_at: string;
  open_alerts: number;
}

export interface AlertsSummary {
  open: number;
  open_by_level: Partial<Record<AlertLevel, number>>;
  last_24h: number;
  last_at?: string;
  rules: number;
  rule_errors: number;
}

export const alertsApi = {
  list: (p: { status?: string; level?: string; rule?: string; before?: number }) =>
    request<{ alerts: Alert[]; configured: boolean }>(
      "GET",
      `/api/v1/alerts?${qs({ status: p.status, level: p.level, rule: p.rule, before: p.before ? String(p.before) : undefined })}`,
    ),
  summary: () => request<{ configured: boolean; summary?: AlertsSummary }>("GET", "/api/v1/alerts/summary"),
  get: (id: number) =>
    request<{ alert: Alert; events: { event_id: string; event_time: string }[]; rule?: RuleInfo }>("GET", `/api/v1/alerts/${id}`),
  setStatus: (id: number, status: AlertStatus, reason?: string) =>
    request<{ alert: Alert }>("POST", `/api/v1/alerts/${id}/status`, { status, reason: reason ?? "" }),
  rules: () => request<{ rules: RuleInfo[]; errors: { file: string; error: string; seen_at: string }[]; configured: boolean }>("GET", "/api/v1/rules"),
};

export const levelLabels: Record<AlertLevel, { label: string; color: string }> = {
  critical: { label: "krytyczny", color: "red" },
  high: { label: "wysoki", color: "orange" },
  medium: { label: "średni", color: "yellow" },
  low: { label: "niski", color: "blue" },
  informational: { label: "informacja", color: "gray" },
};

export const alertStatusLabels: Record<AlertStatus, { label: string; color: string }> = {
  open: { label: "nowy", color: "red" },
  acknowledged: { label: "w analizie", color: "yellow" },
  closed: { label: "zamknięty", color: "gray" },
};
