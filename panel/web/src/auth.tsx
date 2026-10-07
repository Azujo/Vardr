import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, setCsrfToken, setUnauthenticatedHandler, type SessionInfo, type User } from "./api";

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  applySession: (s: SessionInfo) => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const applySession = useCallback((s: SessionInfo) => {
    setCsrfToken(s.csrf_token);
    setUser(s.user);
  }, []);

  useEffect(() => {
    setUnauthenticatedHandler(() => {
      setCsrfToken("");
      setUser(null);
    });
    api
      .session()
      .then(applySession)
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, [applySession]);

  const login = useCallback(
    async (username: string, password: string) => {
      applySession(await api.login(username, password));
    },
    [applySession],
  );

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setCsrfToken("");
      setUser(null);
    }
  }, []);

  return <AuthContext.Provider value={{ user, loading, login, logout, applySession }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth poza AuthProvider");
  return ctx;
}
