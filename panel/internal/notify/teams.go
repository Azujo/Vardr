// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"strings"
	"time"
)

// Wiadomość dla przepływu Power Automate: karta Adaptive Card w kształcie,
// którego oczekuje szablon Teams „Post to a channel when a webhook request
// is received” (type: message, attachments[]), oraz te same dane co ogólny
// webhook w polu „vardr” – dla własnych przepływów (warunki na poziomie
// alertu, zgłoszenie w systemie ticketów, SMS).

// teamsColor: kolor tytułu karty według ważności (nazwy kolorów Adaptive Cards).
var teamsColor = map[string]string{SevCritical: "Attention", SevWarning: "Warning", SevInfo: "Accent", SevOK: "Good"}

// teamsLinkBreaker przerywa składnię linku Markdownu „[tekst](adres)”
// w danych ze zdarzeń (znak zerowej szerokości między „]” a „(”): ukryty
// link w poleceniu procesu nie stanie się klikalnym „Panel” w karcie.
// Karta nie renderuje HTML, a gołe adresy Teams pokazuje w całości.
var teamsLinkBreaker = strings.NewReplacer("](", "]​(")

const (
	teamsMaxFacts = 30
	teamsMaxValue = 1000
	teamsMaxText  = 4000
)

func teamsPayload(m Message) map[string]any {
	text := m.Text
	if m.Untrusted {
		text = teamsLinkBreaker.Replace(text)
	}
	text = clip(text, teamsMaxText)
	body := []any{
		map[string]any{"type": "TextBlock", "text": clip(m.Title, 256), "weight": "Bolder", "size": "Medium", "wrap": true,
			"color": teamsColor[m.Severity]},
	}
	if text != "" {
		body = append(body, map[string]any{"type": "TextBlock", "text": text, "wrap": true})
	}
	var facts, actions []any
	for _, f := range m.Fields {
		v := f.Value
		// Link do panelu (wartość tworzona przez Vardra) – przycisk, nie wiersz.
		if f.Trusted && (strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "http://")) && len(actions) < 3 {
			actions = append(actions, map[string]any{"type": "Action.OpenUrl", "title": "Vardr – " + f.Name, "url": v})
			continue
		}
		if len(facts) == teamsMaxFacts {
			continue
		}
		if m.Untrusted && !f.Trusted {
			v = teamsLinkBreaker.Replace(v)
		}
		v = clip(v, teamsMaxValue)
		facts = append(facts, map[string]any{"title": clip(f.Name, 100), "value": v})
	}
	if facts != nil {
		body = append(body, map[string]any{"type": "FactSet", "facts": facts})
	}
	body = append(body, map[string]any{"type": "TextBlock", "text": "Vardr SIEM · " + m.At.UTC().Format(time.RFC3339),
		"isSubtle": true, "size": "Small", "wrap": true})
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body":    body,
		"msteams": map[string]any{"width": "Full"},
	}
	if actions != nil {
		card["actions"] = actions
	}
	return map[string]any{
		"type": "message",
		"attachments": []any{map[string]any{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"contentUrl":  nil,
			"content":     card,
		}},
		"vardr": webhookPayload(m),
	}
}
