// SPDX-License-Identifier: AGPL-3.0-or-later

// Klient API siem-api. Sesja w ciasteczku HttpOnly (JS jej nie widzi),
// token CSRF w pamięci – dołączany do każdego żądania zmieniającego stan.

import type { WizEvent } from "./corrWizard";

// Rola konta = identyfikator profilu uprawnień (wbudowane: admin, analyst, viewer).
export type Role = string;

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
  source?: "local" | "ldap"; // ldap – konto domenowe (hasło i profil z AD)
}

export interface SessionInfo {
  user: User;
  csrf_token: string;
  server_version?: string;
  mfa?: boolean; // sesja potwierdzona drugim składnikiem
  profile?: { id: string; name: string };
  permissions?: Permissions;
}

// Uprawnienia profilu: moduł → najwyższy poziom (wyższy obejmuje niższe).
export type Permissions = Record<string, string>;
const levelRank: Record<string, number> = { read: 0, test: 1, export: 1, write: 2 };

export function hasPerm(p: Permissions | undefined, mod: string, level: string): boolean {
  const got = p?.[mod];
  return got !== undefined && (levelRank[got] ?? -1) >= (levelRank[level] ?? 99);
}

export interface PermModule {
  key: string;
  label: string;
  help: string;
  levels: { key: string; label: string }[];
}

// Logowanie domenowe (AD przez LDAPS).
export interface LDAPMapping {
  sid: string;
  name: string;
  dn: string;
  profile: string;
}

export interface LDAPConfig {
  enabled: boolean;
  urls: string[];
  ca_pem: string;
  tls_server_name: string;
  bind_dn: string;
  base_dn: string;
  groups_base_dn: string;
  mappings: LDAPMapping[];
}

export interface LDAPGroup {
  sid: string;
  dn: string;
  name: string;
  description: string;
  members: number;
}

export interface LDAPAccountCheck {
  found: boolean;
  account?: { dn: string; sid: string; login: string; upn: string; display_name: string; disabled: boolean };
  groups: number;
  matched: LDAPMapping[];
  profile?: string;
}

export interface Profile {
  id: string;
  name: string;
  description: string;
  permissions: Permissions;
  builtin: boolean;
  users: number;
  admin: boolean;
  updated_by?: string;
  updated_at?: string;
}

// Wynik kroku logowania: sesja albo prośba o kod / konfigurację drugiego składnika.
export type LoginFinal = SessionInfo & { mfa_method?: string; recovery_codes?: string[]; recovery_left?: number };
export type LoginStep = LoginFinal | { mfa: "code" | "enroll"; challenge: string; username: string };

export function isMFAStep(r: LoginStep): r is { mfa: "code" | "enroll"; challenge: string; username: string } {
  return typeof (r as { mfa?: unknown }).mfa === "string";
}

// Konfiguracja aplikacji uwierzytelniającej (kod QR i sekret do wpisania).
export interface MFASetup {
  secret: string;
  uri: string;
  qr: string;
  issuer: string;
  account: string;
}

export interface MFAStatus {
  available: boolean;
  enabled: boolean;
  enabled_at?: string;
  recovery_left?: number;
  policy: MFAPolicy;
  required: boolean;
  session_mfa: boolean;
}

export type MFAPolicy = "all" | "admins" | "none";

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
let onUnauthenticated: (err: ApiError) => void = () => {};

export function setCsrfToken(token: string) {
  csrfToken = token;
}

// Wywoływane, gdy sesja wygaśnie w trakcie pracy (powrót do logowania).
export function setUnauthenticatedHandler(fn: (err: ApiError) => void) {
  onUnauthenticated = fn;
}

export async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
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
    if (res.status === 401 && !path.startsWith("/api/v1/auth/login") && !path.startsWith("/api/v1/auth/mfa") && path !== "/api/v1/auth/session")
      onUnauthenticated(err);
    throw err;
  }
  return data as T;
}

export const api = {
  session: () => request<SessionInfo>("GET", "/api/v1/auth/session"),
  login: (username: string, password: string) => request<LoginStep>("POST", "/api/v1/auth/login", { username, password }),
  loginMFA: (challenge: string, code: string) => request<LoginFinal>("POST", "/api/v1/auth/mfa", { challenge, code }),
  loginEnroll: (challenge: string) => request<MFASetup>("POST", "/api/v1/auth/mfa/enroll", { challenge }),
  loginEnrollConfirm: (challenge: string, code: string) =>
    request<LoginFinal>("POST", "/api/v1/auth/mfa/enroll/confirm", { challenge, code }),
  mfaStatus: () => request<MFAStatus>("GET", "/api/v1/account/mfa"),
  mfaSetup: (password: string) => request<MFASetup>("POST", "/api/v1/account/mfa/setup", { password }),
  mfaConfirm: (code: string) => request<{ recovery_codes: string[] }>("POST", "/api/v1/account/mfa/confirm", { code }),
  mfaDisable: (password: string, code: string) => request<{ ok: boolean }>("POST", "/api/v1/account/mfa/disable", { password, code }),
  mfaRecovery: (password: string, code: string) =>
    request<{ recovery_codes: string[] }>("POST", "/api/v1/account/mfa/recovery", { password, code }),
  resetUserMFA: (id: number, password: string) => request<{ ok: boolean }>("POST", `/api/v1/users/${id}/mfa/reset`, { password }),
  securitySettings: () => request<{ mfa_available: boolean; mfa_policy: MFAPolicy }>("GET", "/api/v1/settings/security"),
  setSecuritySettings: (mfa_policy: MFAPolicy, password: string) =>
    request<{ mfa_policy: MFAPolicy }>("PUT", "/api/v1/settings/security", { mfa_policy, password }),
  logout: () => request<void>("POST", "/api/v1/auth/logout"),
  changePassword: (current_password: string, new_password: string) =>
    request<SessionInfo>("POST", "/api/v1/auth/password", { current_password, new_password }),
  health: () => request<{ status: string; database: string }>("GET", "/api/v1/health"),

  users: () =>
    request<{ users: User[]; mfa?: Record<string, string>; mfa_available?: boolean; mfa_policy?: MFAPolicy }>("GET", "/api/v1/users"),
  createUser: (u: { username: string; display_name: string; role: Role }) =>
    request<{ user: User; temp_password: string }>("POST", "/api/v1/users", u),
  updateUser: (id: number, patch: { display_name?: string; role?: Role; disabled?: boolean }) =>
    request<{ user: User }>("PATCH", `/api/v1/users/${id}`, patch),
  resetPassword: (id: number) =>
    request<{ user: User; temp_password: string }>("POST", `/api/v1/users/${id}/reset-password`),

  permissions: () => request<{ modules: PermModule[] }>("GET", "/api/v1/permissions"),
  ldapSettings: () => request<{ available: boolean; config?: LDAPConfig; has_password?: boolean }>("GET", "/api/v1/settings/ldap"),
  saveLdapSettings: (config: LDAPConfig, bind_password: string, password: string) =>
    request<{ ok: boolean }>("PUT", "/api/v1/settings/ldap", { config, bind_password, password }),
  ldapTest: (config: LDAPConfig, bind_password: string) =>
    request<{ ok: boolean; message?: string; error?: string }>("POST", "/api/v1/settings/ldap/test", { config, bind_password }),
  ldapGroups: (config: LDAPConfig, bind_password: string) =>
    request<{ groups: LDAPGroup[] }>("POST", "/api/v1/settings/ldap/groups", { config, bind_password }),
  ldapCheck: (config: LDAPConfig, bind_password: string, login: string) =>
    request<LDAPAccountCheck>("POST", "/api/v1/settings/ldap/check", { config, bind_password, login }),
  profiles: () => request<{ profiles: Profile[]; editable: boolean }>("GET", "/api/v1/profiles"),
  saveProfile: (id: string, p: { name: string; description: string; permissions: Permissions; password: string }) =>
    request<{ id: string }>("PUT", `/api/v1/profiles/${encodeURIComponent(id)}`, p),
  deleteProfile: (id: string, password: string) =>
    request<{ ok: boolean }>("POST", `/api/v1/profiles/${encodeURIComponent(id)}/delete`, { password }),

  audit: (before?: number) =>
    request<{ entries: AuditEntry[] }>("GET", `/api/v1/audit?limit=100${before ? `&before=${before}` : ""}`),
};

// Nazwy profili wbudowanych (gdy lista profili jeszcze się nie wczytała).
export const roleLabels: Record<string, string> = {
  admin: "Administrator",
  analyst: "Analityk",
  viewer: "Obserwator",
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
  state: "online" | "offline" | "retired";
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
  protection?: "protected" | "open" | "off" | "error" | "other" | "unknown";
  protection_error?: string;
  tamper_24h?: number;
  stopping?: string;
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
  retired?: number;
  with_problems: number;
}

// Status agenta – ten sam dokument co `vardr-agent status` (status.json).
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
  protection?: {
    enabled: boolean;
    service: string;
    error?: string;
    tokens: number;
    events?: TamperRecord[];
  };
  stopping?: string;
}

// Zdarzenie ochrony agenta (dziennik w katalogu stanu agenta).
export interface TamperRecord {
  id: string;
  at: string;
  kind: string;
  detail?: string;
  user?: string;
  token_id?: string;
}

// Rodzaje zdarzeń ochrony: opis i poziom alertu ("" – bez alertu).
export const tamperKinds: Record<string, { title: string; level: string }> = {
  stop: { title: "Usługa zatrzymana bez tokenu", level: "high" },
  unclean_exit: { title: "Proces zakończony bez zatrzymania usługi (zabity albo awaria)", level: "medium" },
  acl_restored: { title: "Zmieniono uprawnienia usługi (przywrócone)", level: "high" },
  config_restored: { title: "Zmieniono konfigurację usługi (przywrócona)", level: "high" },
  bad_token: { title: "Nieudana próba zatrzymania albo deinstalacji (bez ważnego tokenu)", level: "medium" },
  stop_token: { title: "Zatrzymanie tokenem", level: "" },
  uninstall_token: { title: "Deinstalacja tokenem", level: "" },
  upgrade: { title: "Aktualizacja (instalator)", level: "" },
  protection_off: { title: "Ochrona wyłączona w grupie", level: "" },
};

export interface UninstallToken {
  id: number;
  agent_id: string;
  token_id: string;
  reason: string;
  created_by: string;
  created_at: string;
  expires_at: string;
  used_at?: string;
  used_action?: string;
  used_by?: string;
  revoked_at?: string;
  revoked_by?: string;
  state: "active" | "used" | "revoked" | "expired";
}

export const agentsApi = {
  list: () => request<{ agents: AgentView[]; summary: AgentsSummary; offline_after_s: number }>("GET", "/api/v1/agents"),
  get: (id: string) =>
    request<{ agent: AgentView; status: AgentStatusDoc }>("GET", `/api/v1/agents/${encodeURIComponent(id)}`),
  remove: (id: string) => request<void>("DELETE", `/api/v1/agents/${encodeURIComponent(id)}`),
  // Ważne certyfikaty agentów spoza listy (administrator).
  orphanCerts: () =>
    request<{ certs: { serial: string; agent_id: string; hostname: string; not_after: string }[] }>("GET", "/api/v1/agents/orphan-certs"),
  uninstallTokens: (id: string) =>
    request<{ tokens: UninstallToken[] }>("GET", `/api/v1/agents/${encodeURIComponent(id)}/uninstall-tokens`),
  createUninstallToken: (id: string, body: { reason: string; hours?: number; password: string }) =>
    request<{ token: string; item: UninstallToken }>("POST", `/api/v1/agents/${encodeURIComponent(id)}/uninstall-tokens`, body),
  revokeUninstallToken: (id: string, tid: number) =>
    request<void>("POST", `/api/v1/agents/${encodeURIComponent(id)}/uninstall-tokens/${tid}/revoke`),
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
  downloadPackage: (secret: string) => downloadFile("POST", "/api/v1/enroll-tokens/package", { secret }, "vardr-agent.zip"),
  // Jeden plik MSI z adresem serwera i tokenem – instalacja albo aktualizacja podwójnym kliknięciem.
  downloadMSI: (secret: string) => downloadFile("POST", "/api/v1/enroll-tokens/msi", { secret }, "vardr-agent.msi"),
  // Bazowy instalator bez tokenu – aktualizacja zainstalowanych agentów.
  downloadUpdateMSI: () => downloadFile("GET", "/api/v1/agent-update.msi", undefined, "vardr-agent-aktualizacja.msi"),
};

// downloadFile pobiera plik z API (sesja w ciasteczku, CSRF przy POST) i zapisuje go w przeglądarce.
async function downloadFile(method: string, path: string, body: unknown, fallback: string) {
  const res = await fetch(path, {
    method,
    headers: method === "POST" ? { "Content-Type": "application/json", "X-CSRF-Token": csrfToken } : {},
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new ApiError(res.status, data.error ?? "error", data.message ?? `błąd HTTP ${res.status}`);
  }
  const name = /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") ?? "")?.[1] ?? fallback;
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

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
  identity?: string;
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
  heartbeat_alert_min?: number;
  heartbeat_notify_return?: boolean;
  protection?: boolean;
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
  // Pliki na dysku nieznane spisowi – do decyzji administratora.
  unknown?: string[];
}

// Operacja uzgodnienia spisu archiwum z dyskiem (po przywróceniu kopii albo
// decyzja administratora).
export interface ArchiveRecovery {
  id: number;
  kind: "restore" | "adopt" | "quarantine";
  requested_by: string;
  requested_at: string;
  reason: string;
  paths: string[];
  backup?: string;
  window_from?: string;
  window_to?: string;
  verification_id?: number;
  processed_at?: string;
  ok?: boolean;
  error?: string;
  result?: {
    manifests: { seq: number; hour: string; path: string; segments: number; records: number }[];
    segments: { path: string; records: number; bytes: number }[];
    quarantined: string[];
    rejected: { path: string; reason: string }[];
  };
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
  recoveries?: ArchiveRecovery[];
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
  recovery: (action: "adopt" | "quarantine", paths: string[], reason: string, password: string) =>
    request<{ id: number; message: string }>("POST", "/api/v1/archive/recoveries", { action, paths, reason, password }),
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

// ---- Incydenty i zgłoszenia NIS2 ----

export type IncidentSeverity = "low" | "medium" | "high" | "critical";
export type IncidentStatus = "open" | "investigating" | "contained" | "resolved" | "closed";
export type TriState = "yes" | "no" | "unknown";
export type ReportKind = "early_warning" | "notification" | "intermediate" | "final";

export interface Incident {
  id: number;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  assignee: string;
  significant: boolean;
  aware_at?: string;
  malicious: TriState;
  cross_border: TriState;
  impact: string;
  root_cause: string;
  mitigation: string;
  iocs: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  closed_at?: string;
  alert_count: number;
}

export interface IncidentDeadline {
  kind: ReportKind;
  label: string;
  due: string;
  submitted_at?: string;
}

export interface IncidentAlert {
  alert_id: number;
  rule_id: string;
  rule_title: string;
  level: AlertLevel;
  host_name: string;
  agent_id: string;
  user_name: string;
  summary: string;
  first_seen: string;
  last_seen: string;
  added_by: string;
  added_at: string;
}

export interface IncidentActivity {
  id: number;
  at: string;
  username: string;
  kind: string;
  text: string;
  details?: Record<string, unknown>;
}

export interface IncidentReport {
  kind: ReportKind;
  content: string;
  updated_by: string;
  updated_at: string;
  submitted_at?: string;
  submitted_by?: string;
  reference?: string;
}

export interface IncidentRef {
  id: number;
  title: string;
  status: IncidentStatus;
}

export const incidentSeverityLabels: Record<IncidentSeverity, { label: string; color: string }> = {
  low: { label: "niska", color: "gray" },
  medium: { label: "średnia", color: "yellow" },
  high: { label: "wysoka", color: "orange" },
  critical: { label: "krytyczna", color: "red" },
};

export const incidentStatusLabels: Record<IncidentStatus, { label: string; color: string }> = {
  open: { label: "otwarty", color: "red" },
  investigating: { label: "analiza", color: "orange" },
  contained: { label: "opanowany", color: "yellow" },
  resolved: { label: "rozwiązany", color: "teal" },
  closed: { label: "zamknięty", color: "gray" },
};

export const reportKindLabels: Record<ReportKind, string> = {
  early_warning: "Wczesne ostrzeżenie (24 h)",
  notification: "Zgłoszenie incydentu (72 h)",
  intermediate: "Sprawozdanie pośrednie (na wezwanie)",
  final: "Sprawozdanie końcowe (miesiąc)",
};

export const incidentsApi = {
  list: (scope: string) =>
    request<{ incidents: (Incident & { deadlines: IncidentDeadline[] })[]; now: string }>(
      "GET",
      `/api/v1/incidents?scope=${encodeURIComponent(scope)}`,
    ),
  create: (i: { title: string; description: string; severity: IncidentSeverity; alert_ids: number[] }) =>
    request<{ incident: Incident }>("POST", "/api/v1/incidents", i),
  get: (id: number) =>
    request<{
      incident: Incident;
      alerts: IncidentAlert[];
      activity: IncidentActivity[];
      reports: IncidentReport[];
      deadlines: IncidentDeadline[];
      now: string;
    }>("GET", `/api/v1/incidents/${id}`),
  update: (id: number, patch: Partial<Incident> & { comment?: string }) =>
    request<{ incident: Incident }>("PATCH", `/api/v1/incidents/${id}`, patch),
  note: (id: number, text: string) => request<{ ok: boolean }>("POST", `/api/v1/incidents/${id}/notes`, { text }),
  // Wpis o paczce dowodowej – działa też w zamkniętym incydencie.
  evidence: (id: number, text: string) => request<{ ok: boolean }>("POST", `/api/v1/incidents/${id}/evidence`, { text }),
  addAlerts: (id: number, alert_ids: number[]) => request<{ ok: boolean }>("POST", `/api/v1/incidents/${id}/alerts`, { alert_ids }),
  removeAlert: (id: number, alertId: number) =>
    request<{ ok: boolean }>("POST", `/api/v1/incidents/${id}/alerts/${alertId}/remove`, {}),
  draft: (id: number, kind: ReportKind) => request<{ content: string }>("GET", `/api/v1/incidents/${id}/reports/${kind}/draft`),
  saveReport: (id: number, kind: ReportKind, content: string) =>
    request<{ ok: boolean }>("PUT", `/api/v1/incidents/${id}/reports/${kind}`, { content }),
  submitReport: (id: number, kind: ReportKind, content: string, reference: string, submitted_at?: string) =>
    request<{ ok: boolean }>("POST", `/api/v1/incidents/${id}/reports/${kind}/submit`, { content, reference, submitted_at }),
};

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

export type NotifyEvent = "alert" | "incident" | "health" | "anchor";

export interface AlertFilter {
  min_level?: AlertLevel;
  rules_mode?: "only" | "except";
  rules?: string[];
}

export interface NotifyChannel {
  id: number;
  name: string;
  kind: "discord" | "webhook";
  url_hint: string;
  events: NotifyEvent[];
  alert_filter: AlertFilter;
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
  alert_filter?: AlertFilter;
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
  incident: "incydenty: poważne (NIS2) i terminy zgłoszeń",
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
  user_identity?: string;
  source_ip: string;
  first_event_id: string;
  summary: string;
  instructions: string;
  closed_at?: string;
  closed_by?: string;
  close_reason?: string;
  assignee?: string;
}

export interface AlertActivity {
  id: number;
  at: string;
  actor: string;
  kind: "note" | "status" | "assign";
  text?: string;
  details?: { from?: string; to?: string };
}

export interface AlertListFilter {
  status?: string;
  level?: string;
  rule?: string;
  host?: string;
  user?: string;
  assignee?: string;
  engine?: string;
  q?: string;
  since?: string;
  before?: number;
  // MITRE ATT&CK: technika (T1110 – z podtechnikami) albo taktyka (credential-access).
  technique?: string;
  tactic?: string;
}

// Autor i źródło reguły zaimportowanej z SigmaHQ (licencja DRL 1.1 wymaga
// wskazania autora przy alertach z jej trafień).
export interface RuleAttribution {
  author: string;
  source: string;
  rule_url: string;
  license: string;
  license_url: string;
}

// ATT&CK reguły alertu (z tagów; klucz w odpowiedziach – id reguły).
export interface AttackRef {
  id: string;
  name: string;
  url?: string;
}
export interface RuleAttack {
  techniques: AttackRef[];
  tactics: AttackRef[];
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
  threshold?: { count: number; window_s: number; distinct?: string };
  loaded_at: string;
  open_alerts: number;
  file_enabled: boolean;
  version: number;
  override?: { enabled: boolean; trial?: boolean; reason: string; changed_by: string; changed_at: string };
}

// Wynik reguły w trybie próbnym (trafienia bez alertów, od początku próby).
export interface TrialStat {
  rule_id: string;
  since: string;
  changed_by: string;
  reason: string;
  hits: number;
  hosts: number;
  days: { day: string; hits: number }[];
  top_hosts: { host: string; hits: number }[];
  last_at?: string;
  sample_event_id?: string;
  sample_summary?: string;
}

// Zmiana zbiorcza reguł: włączenie, wyłączenie, tryb próbny, ustawienie z pliku.
export type BulkRuleAction = "enable" | "disable" | "trial" | "file";

export interface RuleVersion {
  version: number;
  sha256: string;
  file: string;
  source: string;
  loaded_at: string;
}

export interface RuleTestResult {
  matched: number;
  events: { timestamp: string; event_id: string; host: string; user: string; code: number; summary: string }[];
  alerts: { key?: Record<string, string>; first: string; last: string; events: number; host: string }[];
  alerts_total: number;
  truncated: boolean;
  took_ms: number;
}

export const rulesApi = {
  test: (source: string, hours: number) =>
    request<{
      ok: boolean;
      error?: string;
      result?: RuleTestResult;
      sql?: string;
      attack_warnings?: string[];
      rule?: { id: string; title: string; level: AlertLevel; group_by: string[]; suppress_s: number; mode: string;
        threshold?: { count: number; window_s: number; distinct?: string } };
    }>("POST", "/api/v1/rules/test", { source, hours }),
  versions: (id: string) => request<{ versions: RuleVersion[] }>("GET", `/api/v1/rules/${encodeURIComponent(id)}/versions`),
  setEnabled: (id: string, enabled: boolean | null, reason: string, password?: string, trial = false) =>
    request<{ enabled: boolean; message: string }>("POST", `/api/v1/rules/${encodeURIComponent(id)}/enabled`, {
      enabled,
      trial,
      reason,
      password: password ?? "",
    }),
  bulk: (ids: string[], action: BulkRuleAction, reason: string, password: string) =>
    request<{ changed: number; skipped: number; message: string }>("POST", "/api/v1/rules/bulk", {
      ids,
      action,
      reason,
      password,
    }),
  trials: () => request<{ trials: TrialStat[]; now: string }>("GET", "/api/v1/rules/trial"),
  // Kreator korelacji: przykładowe zdarzenia z polami i pasującymi regułami.
  wizardEvents: (events: { id: string; ts: string }[]) =>
    request<{ events: WizEvent[]; missing: number }>("POST", "/api/v1/rules/wizard/events", { events }),
  panelRule: (id: string) => request<{ rule: PanelRule }>("GET", `/api/v1/panel-rules/${encodeURIComponent(id)}`),
  savePanelRule: (id: string, source: string, note: string) =>
    request<{ ok: boolean; file: string; message: string }>("PUT", `/api/v1/panel-rules/${encodeURIComponent(id)}`, {
      source,
      note,
    }),
  deletePanelRule: (id: string, reason: string, password: string) =>
    request<{ ok: boolean; message: string }>("POST", `/api/v1/panel-rules/${encodeURIComponent(id)}/delete`, {
      reason,
      password,
    }),
};

export interface PanelRule {
  id: string;
  source: string;
  created_by: string;
  created_at: string;
  updated_by: string;
  updated_at: string;
}

// Reguły zapisane w panelu mają plik panel/<id korelacji>.yml.
export function panelRuleId(file: string): string | null {
  const m = /^panel\/(.+)\.yml$/.exec(file);
  return m ? m[1] : null;
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
  list: (p: AlertListFilter) =>
    request<{ alerts: Alert[]; total: number; configured: boolean; attack?: Record<string, RuleAttack> }>(
      "GET",
      `/api/v1/alerts?${qs({ ...p, before: p.before ? String(p.before) : undefined })}`,
    ),
  summary: () => request<{ configured: boolean; summary?: AlertsSummary }>("GET", "/api/v1/alerts/summary"),
  get: (id: number) =>
    request<{
      alert: Alert;
      events: { event_id: string; event_time: string }[];
      rule?: RuleInfo;
      activity: AlertActivity[];
      related: Alert[];
      attack?: Record<string, RuleAttack>;
      attribution?: RuleAttribution;
      incidents?: IncidentRef[];
    }>("GET", `/api/v1/alerts/${id}`),
  setStatus: (id: number, status: AlertStatus, reason?: string) =>
    request<{ alert: Alert }>("POST", `/api/v1/alerts/${id}/status`, { status, reason: reason ?? "" }),
  bulkStatus: (ids: number[], status: AlertStatus, reason?: string) =>
    request<{ changed: number; ids: number[] }>("POST", "/api/v1/alerts/bulk-status", { ids, status, reason: reason ?? "" }),
  assign: (id: number, assignee: string) => request<{ alert: Alert }>("POST", `/api/v1/alerts/${id}/assign`, { assignee }),
  addNote: (id: number, text: string) =>
    request<{ activity: AlertActivity[] }>("POST", `/api/v1/alerts/${id}/notes`, { text }),
  assignees: () =>
    request<{ assignees: { username: string; display_name: string }[] }>("GET", "/api/v1/alert-assignees"),
  rules: () =>
    request<{
      rules: RuleInfo[];
      errors: { file: string; error: string; seen_at: string }[];
      configured: boolean;
      attributions?: Record<string, RuleAttribution>;
    }>("GET", "/api/v1/rules"),
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

// ---- Himinbjörg: stan systemu ----

export interface SystemCheck {
  group: string;
  name: string;
  status: "ok" | "warn" | "crit" | "unknown" | "off";
  value: string;
  hint?: string;
}

export interface SystemReport {
  overall: SystemCheck["status"];
  checks: SystemCheck[];
  generated_at: string;
}

export const systemApi = {
  get: () => request<{ configured: boolean; report?: SystemReport; grafana_url?: string }>("GET", "/api/v1/system"),
};

// ---- Dekodery syslog ----

export interface DecoderInfo {
  id: string;
  title: string;
  description?: string;
  dataset: string;
  priority: number;
  version: number;
  origin: "builtin" | "custom";
  modified: boolean;
  enabled: boolean;
  order: number;
  source: string;
  builtin_source?: string;
  samples: number;
  revision?: number;
  updated_at?: string;
  updated_by?: string;
  error?: string;
}

export interface DecoderVersion {
  id: number;
  decoder_id: string;
  revision: number;
  action: "saved" | "enabled" | "disabled" | "reverted";
  source: string;
  enabled: boolean;
  note?: string;
  changed_at: string;
  changed_by: string;
}

export interface DecodeResult {
  raw: string;
  header: { format: string; host?: string; app?: string; pid?: string; severity?: string; facility?: number; time?: string; message: string };
  candidate: boolean;
  decoder: string;
  dataset: string;
  pattern: boolean;
  event: Record<string, string>;
  fields: Record<string, string>;
  error?: string;
}

export interface DecoderTestResponse {
  ok: boolean;
  error?: string;
  decoder?: { id: string; title: string; dataset: string; priority: number };
  results?: DecodeResult[];
  summary?: Record<"total" | "candidate" | "other" | "generic" | "errors" | "no_pattern", number>;
}

export interface SyslogSample {
  timestamp: string;
  peer: string;
  host: string;
  dataset: string;
  decoder?: string;
  raw: string;
}

export const decodersApi = {
  list: () =>
    request<{ decoders: DecoderInfo[]; delivery: boolean; samples: boolean; targets: string[] }>("GET", "/api/v1/decoders"),
  test: (source: string, samples: string[], peer: string) =>
    request<DecoderTestResponse>("POST", "/api/v1/decoders/test", { source, samples, peer }),
  samples: (p: { decoder?: string; peer?: string; hours?: number; limit?: number }) => {
    const q = new URLSearchParams();
    if (p.decoder) q.set("decoder", p.decoder);
    if (p.peer) q.set("peer", p.peer);
    q.set("hours", String(p.hours ?? 24));
    q.set("limit", String(p.limit ?? 50));
    return request<{ samples: SyslogSample[] }>("GET", `/api/v1/decoders/samples?${q}`);
  },
  versions: (id: string) => request<{ versions: DecoderVersion[] }>("GET", `/api/v1/decoders/${encodeURIComponent(id)}/versions`),
  save: (id: string, source: string, note: string) =>
    request<{ ok: boolean; revision: number; message: string }>("PUT", `/api/v1/decoders/${encodeURIComponent(id)}`, { source, note }),
  setEnabled: (id: string, enabled: boolean, reason: string, password?: string) =>
    request<{ ok: boolean; message: string }>("POST", `/api/v1/decoders/${encodeURIComponent(id)}/enabled`, {
      enabled,
      reason,
      password: password ?? "",
    }),
  revert: (id: string, reason: string, password?: string) =>
    request<{ ok: boolean; message: string }>("POST", `/api/v1/decoders/${encodeURIComponent(id)}/revert`, {
      reason,
      password: password ?? "",
    }),
};

// ---- Kwarantanna ----

export interface QuarantineGroup {
  source: string;
  reason: string;
  count: number;
  agents: number;
  first: string;
  last: string;
  example_event_id: string;
}

export interface QuarantineEntry {
  ingested: string;
  agent_id: string;
  event_id: string;
  source: string;
  reason: string;
  peer?: string;
  raw: string;
  raw_bytes: number;
  truncated?: boolean;
  supported: boolean;
  outcome?: { job_id: number; recovered: boolean; reason?: string; at: string };
}

export interface QuarantineJob {
  id: number;
  created_at: string;
  created_by: string;
  filter: { source?: string; reason?: string; agent?: string; event_ids?: string[]; from?: string };
  status: "running" | "done" | "failed";
  total: number;
  recovered: number;
  failed: number;
  finished_at?: string;
  error?: string;
}

export interface QuarantineFilterParams {
  hours: number;
  source?: string;
  reason?: string;
  agent?: string;
}

export const quarantineApi = {
  list: (f: QuarantineFilterParams) => {
    const q = new URLSearchParams({ hours: String(f.hours) });
    if (f.source) q.set("source", f.source);
    if (f.reason) q.set("reason", f.reason);
    if (f.agent) q.set("agent", f.agent);
    return request<{
      groups: QuarantineGroup[];
      entries: QuarantineEntry[];
      total: number;
      jobs: QuarantineJob[];
      reprocess: boolean;
      running: boolean;
    }>("GET", `/api/v1/quarantine?${q}`);
  },
  reprocess: (f: QuarantineFilterParams & { event_ids?: string[] }) =>
    request<{ job: QuarantineJob; limited: boolean }>("POST", "/api/v1/quarantine/reprocess", f),
};

// ---- Tożsamości osób ----

export interface IdentityAlias {
  alias: string;
  identity: string;
  note?: string;
  created_at: string;
  created_by: string;
}

export interface Person {
  identity: string;
  events: number;
  failures: number;
  last: string;
  datasets: string[];
  accounts: string[];
  hosts: number;
}

export const identitiesApi = {
  get: () =>
    request<{ domains: string[]; aliases: IdentityAlias[]; shared: string[]; delivery: boolean; people: boolean }>("GET", "/api/v1/identities"),
  people: (hours: number, q: string) =>
    request<{ people: Person[]; suggestions: { identities: string[] }[] }>(
      "GET",
      `/api/v1/identities/people?hours=${hours}&q=${encodeURIComponent(q)}`,
    ),
  resolve: (user: string, domain: string, host = "") =>
    request<{ identity: string }>(
      "GET",
      `/api/v1/identities/resolve?user=${encodeURIComponent(user)}&domain=${encodeURIComponent(domain)}&host=${encodeURIComponent(host)}`,
    ),
  setDomains: (domains: string[]) =>
    request<{ domains: string[]; message: string }>("PUT", "/api/v1/identities/domains", { domains }),
  setShared: (accounts: string[]) =>
    request<{ accounts: string[]; message: string }>("PUT", "/api/v1/identities/shared", { accounts }),
  setAlias: (alias: string, identity: string, note: string) =>
    request<{ message: string }>("POST", "/api/v1/identities/aliases", { alias, identity, note }),
  deleteAlias: (alias: string) => request<{ message: string }>("POST", "/api/v1/identities/aliases/delete", { alias }),
  domainsSeen: () =>
    request<{ domains: { domain: string; events: number; covered: boolean }[] }>("GET", "/api/v1/identities/domains-seen"),
};

// ---- Kopie zapasowe (siem-backup) ----

export type BackupMethod = "none" | "sftp" | "smb" | "s3";
export type BackupAuth = "server_key" | "private_key" | "password";

export interface BackupConfig {
  enabled: boolean;
  schedule: { kind: "hours" | "daily" | "weekly"; every_hours?: number; hour: number; minute: number; weekday?: number };
  include: { saga: boolean; config: boolean; archive: boolean; grafana: boolean };
  local: { keep_days: number; keep_count: number };
  remote: { keep_days: number; keep_count: number };
  target: {
    method: BackupMethod;
    host?: string;
    port?: number;
    user?: string;
    auth?: BackupAuth;
    share?: string;
    domain?: string;
    path?: string;
    endpoint?: string;
    region?: string;
    bucket?: string;
    access_key?: string;
  };
}

export interface BackupRun {
  id: number;
  kind: "scheduled" | "manual";
  started_at: string;
  finished_at?: string;
  status: "running" | "ok" | "partial" | "error";
  file: string;
  size_bytes: number;
  remote: "" | "ok" | "error";
  message: string;
}

export type BackupPart = "saga" | "config" | "grafana";

export interface BackupFile {
  location: "local" | "remote";
  name: string;
  size_bytes: number;
  modified?: string;
  contents: BackupPart[] | null;
  note?: string;
  listed_at: string;
}

export interface BackupRequest {
  id: number;
  action: "run" | "test" | "genkey" | "list" | "inspect" | "restore";
  params?: { location?: string; name?: string; parts?: BackupPart[]; safety_backup?: boolean };
  requested_at: string;
  requested_by: string;
  started_at?: string;
  done_at?: string;
  ok?: boolean;
  message: string;
}

export interface BackupView {
  state: {
    config: BackupConfig;
    saved: boolean;
    updated_at?: string;
    updated_by?: string;
    secrets: { name: string; key_id: string; updated_at: string; updated_by: string }[];
    runner: {
      key_id: string;
      ssh_public_key: string;
      host_key: string;
      pass_id: string;
      local_dir: string;
      local_free: number;
      version: string;
      seen_at?: string;
    } | null;
    runs: BackupRun[];
    requests: BackupRequest[];
    files: BackupFile[];
  };
  online: boolean;
  stale_secrets: string[];
  needed_secrets: string[];
}

export const backupApi = {
  get: () => request<BackupView>("GET", "/api/v1/backup"),
  save: (config: BackupConfig, secrets: Record<string, string>, password: string) =>
    request<{ message: string }>("PUT", "/api/v1/backup", { config, secrets, password }),
  request: (action: "run" | "test" | "genkey" | "list" | "inspect", file?: { location: string; name: string }) =>
    request<{ request: BackupRequest }>("POST", "/api/v1/backup/requests", { action, ...file }),
  restore: (file: { location: string; name: string }, parts: BackupPart[], safety_backup: boolean, confirm: string, password: string) =>
    request<{ request: BackupRequest; message: string }>("POST", "/api/v1/backup/restore", {
      ...file,
      parts,
      safety_backup,
      confirm,
      password,
    }),
};
