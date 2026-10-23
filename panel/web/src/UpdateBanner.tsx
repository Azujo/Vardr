// SPDX-License-Identifier: AGPL-3.0-or-later

// Pasek „panel został zaktualizowany”: otwarta karta pobiera nowe dane, ale
// kod strony wymienia dopiero po przeładowaniu – stary kod potrafi błędnie
// pokazać nowe dane (np. nieznany stan agenta). Strona co minutę i przy
// powrocie do karty porównuje swój plik JS z tym, który podaje index.html.
import { useEffect, useState } from "react";
import { Alert, Button, Group, Text } from "@mantine/core";
import { IconRefresh } from "@tabler/icons-react";
import { useTranslation } from "react-i18next";

const bundleRe = /assets\/index-[^"']+\.js/;

function loadedBundle(): string | null {
  for (const s of Array.from(document.scripts)) {
    const m = bundleRe.exec(s.src);
    if (m) return m[0];
  }
  return null; // tryb deweloperski (vite) – bez sprawdzania
}

export default function UpdateBanner() {
  const { t } = useTranslation();
  const [outdated, setOutdated] = useState(false);
  useEffect(() => {
    const mine = loadedBundle();
    if (!mine) return;
    let stop = false;
    const check = async () => {
      if (stop || document.visibilityState !== "visible") return;
      try {
        const html = await (await fetch("/", { cache: "no-store", credentials: "same-origin" })).text();
        const served = bundleRe.exec(html)?.[0];
        if (served && served !== mine) setOutdated(true);
      } catch {
        // brak sieci albo restart serwera – sprawdzimy przy następnej okazji
      }
    };
    const t = setInterval(() => void check(), 60_000);
    const onVisible = () => void check();
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      stop = true;
      clearInterval(t);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);
  if (!outdated) return null;
  return (
    <Alert color="blue" variant="light" mb="md" py={8}>
      <Group justify="space-between" wrap="nowrap">
        <Text size="sm">{t("update.text")}</Text>
        <Button size="xs" leftSection={<IconRefresh size={14} />} onClick={() => window.location.reload()}>
          {t("update.reload")}
        </Button>
      </Group>
    </Alert>
  );
}
