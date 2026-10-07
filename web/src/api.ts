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
