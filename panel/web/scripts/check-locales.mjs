// SPDX-License-Identifier: AGPL-3.0-or-later

// Kompletność tłumaczeń panelu (uruchamiane przed budowaniem).
// Źródłem kluczy jest polski (src/locales/pl); errors.json – angielski, bo
// polskie opisy błędów przychodzą z serwera (kody sprawdza test Go
// TestErrorCodesTranslated). Języki z listy required muszą mieć wszystkie
// klucze – inaczej budowanie się przerywa; pozostałe dostają raport z
// procentem przetłumaczenia (brakujące teksty panel pokazuje po angielsku).
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const dir = fileURLToPath(new URL("../src/locales/", import.meta.url));
const required = ["en"];

// Klucze płaskie (a.b.c) bez końcówek liczby mnogiej – języki mają ich różne zestawy.
function keys(obj, prefix = "", out = new Set()) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix + k;
    if (v && typeof v === "object") keys(v, key + ".", out);
    else out.add(key.replace(/_(zero|one|two|few|many|other)$/, ""));
  }
  return out;
}

function load(lang, ns) {
  try {
    return keys(JSON.parse(readFileSync(join(dir, lang, ns), "utf8")));
  } catch (e) {
    if (e.code === "ENOENT") return new Set();
    throw new Error(`${lang}/${ns}: ${e.message}`);
  }
}

const langs = readdirSync(dir).filter((l) => l !== "pl");
const namespaces = readdirSync(join(dir, "pl")).filter((f) => f.endsWith(".json"));
let failed = false;

for (const lang of langs) {
  let total = 0;
  let have = 0;
  const problems = [];
  for (const ns of namespaces) {
    const src = ns === "errors.json" ? load("en", ns) : load("pl", ns);
    const got = load(lang, ns);
    for (const k of src) {
      total++;
      if (got.has(k)) have++;
      else problems.push(`brak ${ns.replace(".json", "")}:${k}`);
    }
    for (const k of got) if (!src.has(k)) problems.push(`zbędny ${ns.replace(".json", "")}:${k}`);
  }
  const pct = total ? Math.floor((have / total) * 100) : 100;
  const must = required.includes(lang);
  console.log(`tłumaczenia ${lang}: ${pct}% (${have}/${total})${must ? " – wymagane 100%" : ""}`);
  if (must && problems.length) {
    failed = true;
    for (const p of problems) console.error(`  ${lang}: ${p}`);
  }
}
if (failed) process.exit(1);
