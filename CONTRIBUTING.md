# Jak współtworzyć Vardra

Dziękujemy za chęć pomocy! Zgłoszenia błędów i pomysły: GitHub Issues. Podatności bezpieczeństwa zgłaszaj prywatnie (nie w publicznym zgłoszeniu) – szczegóły w `SECURITY.md`.

## Licencja wkładu

Vardr jest na licencji [AGPL-3.0-or-later](LICENSE). Przesyłając zmiany (pull request, poprawkę), udostępniasz je na tej samej licencji.

Każdy commit musi mieć potwierdzenie [Developer Certificate of Origin 1.1](https://developercertificate.org/) – oświadczenie, że masz prawo przekazać ten kod na licencji projektu. Wystarczy linia na końcu opisu commita, dodawana automatycznie przez:

```bash
git commit -s
```

```
Signed-off-by: Imię Nazwisko <adres@example.com>
```

## Zasady

- Nowe pliki źródłowe zaczynają się od nagłówka licencji: `// SPDX-License-Identifier: AGPL-3.0-or-later` (Go, TypeScript) albo `# SPDX-License-Identifier: AGPL-3.0-or-later` (skrypty, po linii `#!`).
- Komentarze, komunikaty i dokumentacja – po polsku, jak w reszcie projektu.
- Przed wysłaniem: `go vet ./...`, `go test ./...`, a dla panelu `npm run build` w `panel/web`. Budowanie, testy i konwencje: [docs/rozwoj.md](docs/rozwoj.md).
- Nowe reguły detekcji: [docs/reguly.md](docs/reguly.md) (reguła z testem na korpusie).
