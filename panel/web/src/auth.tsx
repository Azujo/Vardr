import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { ApiError, api, hasPerm, setCsrfToken, setUnauthenticatedHandler, type Permissions, type SessionInfo, type User } from "./api";

interface AuthState {
  user: User | null;
  loading: boolean;
  // notice: powód wylogowania pokazywany na stronie logowania (np. nowy wymóg MFA).
  notice: string;
  // Profil konta i sprawdzenie uprawnienia (moduł, poziom).
  profile: { id: string; name: string } | null;
  can: (mod: string, level: string) => boolean;
  logout: () => Promise<void>;
  applySession: (s: SessionInfo) => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState("");
  const [perms, setPerms] = useState<Permissions>({});
  const [profile, setProfile] = useState<{ id: string; name: string } | null>(null);
  const can = useCallback((mod: string, level: string) => hasPerm(perms, mod, level), [perms]);

  const applySession = useCallback((s: SessionInfo) => {
    setCsrfToken(s.csrf_token);
    setUser(s.user);
    setPerms(s.permissions ?? {});
    setProfile(s.profile ?? null);
    setNotice("");
  }, []);

  useEffect(() => {
    setUnauthenticatedHandler((err) => {
      setCsrfToken("");
      setUser(null);
      if (err.code === "mfa_required") setNotice(err.message);
    });
    api
      .session()
      .then(applySession)
      .catch((e) => {
        setUser(null);
        if (e instanceof ApiError && e.code === "mfa_required") setNotice(e.message);
      })
      .finally(() => setLoading(false));
  }, [applySession]);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setCsrfToken("");
      setUser(null);
    }
  }, []);

  return <AuthContext.Provider value={{ user, loading, notice, profile, can, logout, applySession }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth poza AuthProvider");
  return ctx;
}
