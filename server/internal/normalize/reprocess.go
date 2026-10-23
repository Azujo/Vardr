// SPDX-License-Identifier: AGPL-3.0-or-later

package normalize

import (
	"strconv"
	"time"

	"siem/internal/contract"
	"siem/internal/model"
	"siem/internal/reprocess"
)

// Reprocess normalizuje wpisy kwarantanny bieżącym kodem i dekoderami.
// Odzyskane zdarzenia (pogrupowane według agenta) dostają czas przyjęcia
// now – silnik zapytań detekcji czyta po czasie przyjęcia, więc zobaczy je
// jak nowe – a w polach: numer zlecenia i pierwotny czas przyjęcia.
func Reprocess(req reprocess.Request, now time.Time) (map[string][]model.Event, reprocess.Reply) {
	out := map[string][]model.Event{}
	var rep reprocess.Reply
	for _, it := range req.Items {
		if !reprocess.Supported(it.Source) || it.AgentID == "" || it.EventID == "" {
			rep.Failed = append(rep.Failed, reprocess.Failure{EventID: it.EventID,
				Reason: "an entry from source \"" + it.Source + "\" cannot be reprocessed"})
			continue
		}
		e, err := Event(contract.Event{ID: it.EventID, Source: it.Source, Raw: it.Raw, Peer: it.Peer, Truncated: it.Truncated},
			it.AgentID, now)
		if err != nil {
			rep.Failed = append(rep.Failed, reprocess.Failure{EventID: it.EventID, Reason: err.Error()})
			continue
		}
		if e.Fields == nil {
			e.Fields = map[string]string{}
		}
		e.Fields["siem.reprocess_job"] = strconv.FormatInt(req.Job, 10)
		if !it.Ingested.IsZero() {
			e.Fields["siem.quarantined_at"] = it.Ingested.UTC().Format(time.RFC3339Nano)
		}
		out[it.AgentID] = append(out[it.AgentID], e)
		rep.Recovered = append(rep.Recovered, it.EventID)
	}
	return out, rep
}
