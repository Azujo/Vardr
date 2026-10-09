package normalize

import (
	"time"

	"siem/internal/contract"
	"siem/internal/model"
)

// Batch normalizuje paczkę agenta. Zdarzenia, których nie da się
// znormalizować, trafiają do kwarantanny z oryginałem i powodem –
// błąd jednego zdarzenia nie zatrzymuje pozostałych.
func Batch(b contract.Batch, agentID string, ingested time.Time) model.Batch {
	out := model.Batch{BatchID: b.BatchID, AgentID: agentID, Events: make([]model.Event, 0, len(b.Events))}
	for _, ev := range b.Events {
		e, err := Event(ev, agentID, ingested)
		if err != nil {
			out.Quarantine = append(out.Quarantine, model.Quarantined{
				Ingested: ingested.UTC(), AgentID: agentID, EventID: ev.ID,
				Source: ev.Source, Reason: err.Error(), Raw: ev.Raw,
			})
			continue
		}
		out.Events = append(out.Events, e)
	}
	return out
}
