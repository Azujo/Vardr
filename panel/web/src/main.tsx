// SPDX-License-Identifier: AGPL-3.0-or-later

import "@mantine/core/styles.css";
import "@mantine/notifications/styles.css";

import { StrictMode, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { Badge, MantineProvider, createTheme, localStorageColorSchemeManager } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import "./i18n";
import { AuthProvider } from "./auth";
import App from "./App";

const theme = createTheme({
  primaryColor: "indigo",
  defaultRadius: "md",
  fontFamily: "Inter, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
  headings: { fontWeight: "650" },
  components: {
    // Etykiety stanu bez wersalików – czytelniejsze i nie ucinają się w tabelach.
    // Etykieta nie skraca się do „onli…” – kolumna tabeli dopasowuje się do niej.
    Badge: Badge.extend({ styles: { root: { textTransform: "none", flexShrink: 0 }, label: { overflow: "visible" } } }),
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <MantineProvider
      theme={theme}
      defaultColorScheme="auto"
      colorSchemeManager={localStorageColorSchemeManager({ key: "heimdall-color-scheme" })}
    >
      <Notifications position="top-right" />
      <BrowserRouter>
        {/* Tłumaczenia ładują się w tle – do tego czasu pusty ekran (ułamek sekundy). */}
        <Suspense fallback={null}>
          <AuthProvider>
            <App />
          </AuthProvider>
        </Suspense>
      </BrowserRouter>
    </MantineProvider>
  </StrictMode>,
);
