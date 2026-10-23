// SPDX-License-Identifier: AGPL-3.0-or-later

// Tłumaczenia panelu: pliki JSON w locales/<język>/<moduł>.json, ładowane
// przez przeglądarkę dopiero wtedy, gdy są potrzebne (osobne pliki w
// paczce Vite) – serwer niczego nie tłumaczy. Polski jest językiem źródłowym,
// angielski – zapasowym dla pozostałych języków.
import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import resourcesToBackend from "i18next-resources-to-backend";

// Języki z tłumaczeniami: kod → nazwa we własnym języku (do przełącznika).
export const languages: Record<string, string> = {
  pl: "Polski",
  en: "English",
};

const storageKey = "vardr-language";

// Język przed zalogowaniem: ostatnio używany w tej przeglądarce, potem
// preferencje przeglądarki; nieobsługiwany – angielski.
function initialLanguage(): string {
  try {
    const saved = localStorage.getItem(storageKey);
    if (saved && saved in languages) return saved;
  } catch {
    /* tryb prywatny – bez zapamiętywania */
  }
  for (const l of navigator.languages ?? [navigator.language]) {
    const base = l.toLowerCase().split("-")[0];
    if (base in languages) return base;
  }
  return "en";
}

void i18n
  .use(initReactI18next)
  .use(resourcesToBackend((lng: string, ns: string) => import(`./locales/${lng}/${ns}.json`)))
  .init({
    lng: initialLanguage(),
    supportedLngs: Object.keys(languages),
    // Brak tłumaczenia: angielski, a gdy i tam brak – polski (źródło).
    fallbackLng: (code) => (code === "pl" ? [] : code === "en" ? ["pl"] : ["en", "pl"]),
    ns: ["common", "errors"],
    defaultNS: "common",
    interpolation: { escapeValue: false }, // React sam escapuje
    returnNull: false,
  });

i18n.on("languageChanged", (lng) => {
  document.documentElement.lang = lng;
});
document.documentElement.lang = i18n.language;

// Zmiana języka w tej przeglądarce ("" – według przeglądarki).
export function setLanguage(lang: string) {
  try {
    if (lang) localStorage.setItem(storageKey, lang);
    else localStorage.removeItem(storageKey);
  } catch {
    /* bez zapamiętywania */
  }
  void i18n.changeLanguage(lang || initialLanguage());
}

// Tag języka dla Intl (daty, liczby).
export function locale(): string {
  return i18n.resolvedLanguage ?? i18n.language ?? "pl";
}

// Komunikat błędu API: serwer zwraca stały kod i opis po polsku (część
// błędów – walidacja ustawień, reguł, dekoderów – także po angielsku,
// message_en). W innym języku panel bierze opis angielski albo tłumaczy kod
// (locales/<język>/errors.json); nieznany kod – opis z serwera.
export function errorMessage(code: string, serverMessage: string, messageEn?: string): string {
  if (locale() === "pl") return serverMessage;
  if (messageEn) return messageEn;
  return i18n.exists(code, { ns: "errors" }) ? i18n.t(code, { ns: "errors" }) : serverMessage;
}

// Tekst z serwera w dwóch wersjach (np. błąd reguły: error, error_en).
export function serverText(pl: string, en?: string): string {
  return locale() !== "pl" && en ? en : pl;
}

export default i18n;
