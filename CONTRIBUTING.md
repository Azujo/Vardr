# Contributing to Vardr

🇬🇧 English · 🇵🇱 [Polski](#jak-współtworzyć-vardra)

Thank you for wanting to help! Bug reports and ideas: GitHub Issues. Report security vulnerabilities privately (not in a public issue) – details in [SECURITY.md](SECURITY.md). Issues and pull requests in English or Polish are welcome.

## License of contributions

Vardr is licensed under [AGPL-3.0-or-later](LICENSE). By submitting changes (a pull request, a patch) you make them available under the same license.

Every commit must carry a [Developer Certificate of Origin 1.1](https://developercertificate.org/) sign-off – a statement that you have the right to contribute the code under the project's license. A line at the end of the commit message is enough, added automatically by:

```bash
git commit -s
```

```
Signed-off-by: Your Name <address@example.com>
```

## Rules

- New source files start with the license header: `// SPDX-License-Identifier: AGPL-3.0-or-later` (Go, TypeScript) or `# SPDX-License-Identifier: AGPL-3.0-or-later` (scripts, after the `#!` line).
- Code comments are in Polish, like the rest of the project; identifiers, commit messages and service logs in English. Texts for people are bilingual: panel texts in the translation files `panel/web/src/locales/` (Polish and English), server texts through `internal/lang`. Translations of the panel into other languages are very welcome: [docs/en/development.md – panel translations](docs/en/development.md#panel-translations).
- Before submitting: `go vet ./...`, `go test ./...`, and for the panel `npm run build` in `panel/web`. Building, tests and conventions: [docs/en/development.md](docs/en/development.md).
- New detection rules: [docs/en/rules.md](docs/en/rules.md) (a rule with a test on the corpus and an English translation in `vardr.i18n.en`).

---

# Jak współtworzyć Vardra

Dziękujemy za chęć pomocy! Zgłoszenia błędów i pomysły: GitHub Issues. Podatności bezpieczeństwa zgłaszaj prywatnie (nie w publicznym zgłoszeniu) – szczegóły w [SECURITY.md](SECURITY.md).

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
- Komentarze w kodzie – po polsku, jak w reszcie projektu; identyfikatory, opisy commitów i logi usług – po angielsku. Teksty dla ludzi – w dwóch językach: panelu w plikach tłumaczeń `panel/web/src/locales/` (polski i angielski), serwera przez `internal/lang`. Nowe tłumaczenia panelu na inne języki są bardzo mile widziane: [docs/rozwoj.md – tłumaczenie panelu](docs/rozwoj.md#tłumaczenie-panelu).
- Przed wysłaniem: `go vet ./...`, `go test ./...`, a dla panelu `npm run build` w `panel/web`. Budowanie, testy i konwencje: [docs/rozwoj.md](docs/rozwoj.md).
- Nowe reguły detekcji: [docs/reguly.md](docs/reguly.md) (reguła z testem na korpusie i tłumaczeniem `vardr.i18n.en`).
