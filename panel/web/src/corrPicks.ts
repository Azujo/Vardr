// SPDX-License-Identifier: AGPL-3.0-or-later

// Zdarzenia wybrane do kreatora korelacji (z wyszukiwarki zdarzeń).
// Trzymane w sessionStorage tej karty – wygoda, nie stan do zachowania;
// bez dostępu do magazynu lista żyje tylko w pamięci strony.
import { useEffect, useState } from "react";

export interface Pick {
  id: string;
  ts: string;
  label: string;
}

export const maxPicks = 10;
const storageKey = "heimdall.corrPicks";
const changed = "heimdall-corr-picks";
let memory: Pick[] = [];

export function getPicks(): Pick[] {
  try {
    const raw = sessionStorage.getItem(storageKey);
    if (raw) return JSON.parse(raw) as Pick[];
  } catch {
    // brak dostępu do magazynu – lista w pamięci
  }
  return memory;
}

export function setPicks(p: Pick[]) {
  memory = p.slice(0, maxPicks);
  try {
    sessionStorage.setItem(storageKey, JSON.stringify(memory));
  } catch {
    // jak wyżej
  }
  window.dispatchEvent(new Event(changed));
}

export function togglePick(p: Pick): boolean {
  const cur = getPicks();
  if (cur.some((x) => x.id === p.id)) {
    setPicks(cur.filter((x) => x.id !== p.id));
    return false;
  }
  if (cur.length >= maxPicks) return false;
  setPicks([...cur, p]);
  return true;
}

export function usePicks(): Pick[] {
  const [picks, set] = useState<Pick[]>(getPicks);
  useEffect(() => {
    const h = () => set(getPicks());
    window.addEventListener(changed, h);
    return () => window.removeEventListener(changed, h);
  }, []);
  return picks;
}
