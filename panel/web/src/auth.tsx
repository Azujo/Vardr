// SPDX-License-Identifier: AGPL-3.0-or-later

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { setLanguage } from "./i18n";
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
  // Język zapisany na koncie zmieniony w tej sesji (bez ponownego pobierania sesji).
  setUserLanguage: (language: string) => void;
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
    // Język zapisany na koncie wygrywa z językiem tej przeglądarki.
    if (s.user.language) setLanguage(s.user.language);
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

  const setUserLanguage = useCallback((language: string) => {
    setUser((u) => (u ? { ...u, language } : u));
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setCsrfToken("");
      setUser(null);
    }
  }, []);

  return <AuthContext.Provider value={{ user, loading, notice, profile, can, logout, applySession, setUserLanguage }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth poza AuthProvider");
  return ctx;
}
