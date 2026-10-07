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
      `/api/v1/events/histogram?${qs({ q: p.q, from: p.from, to: p.to })}`,
    ),
  get: (id: string, ts: string) =>
    request<{ event: EventDetail }>("GET", `/api/v1/events/${encodeURIComponent(id)}?${qs({ ts })}`),
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

export type Compliance = "ok" | "problems" | "archiver_down" | "stale" | "never_verified" | "not_configured";

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
}

export interface ArchiveOverview {
  compliance: Compliance;
  archiver?: ArchiverState | null;
  archiver_running?: boolean;
  summary?: ArchiveSummary;
  last_verification?: ArchiveVerification | null;
  manifests?: ArchiveManifest[];
  verifications?: ArchiveVerification[];
}

export const archiveApi = {
  overview: () => request<ArchiveOverview>("GET", "/api/v1/archive"),
  verify: () => request<{ message: string }>("POST", "/api/v1/archive/verify"),
};

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
