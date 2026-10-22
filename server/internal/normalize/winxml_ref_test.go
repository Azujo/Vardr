// SPDX-License-Identifier: AGPL-3.0-or-later

package normalize

import (
	"bytes"
	"encoding/xml"
	"strings"
)

// Wzorzec: dotychczasowy parser oparty na encoding/xml. Nowy parser
// (parseWinEvent) musi dawać identyczne wyniki – sprawdzają to testy
// porównawcze i fuzzing.

type refWinEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Level       string `xml:"Level"`
		Task        string `xml:"Task"`
		Keywords    string `xml:"Keywords"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID string `xml:"EventRecordID"`
		Channel       string `xml:"Channel"`
		Computer      string `xml:"Computer"`
		Security      struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	UserData struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"UserData"`
}

func refParseWinEvent(raw string) (winEvent, error) {
	var r refWinEvent
	if err := xml.Unmarshal([]byte(raw), &r); err != nil {
		return winEvent{}, err
	}
	w := winEvent{
		Provider: r.System.Provider.Name, EventID: r.System.EventID, Level: r.System.Level,
		Task: r.System.Task, Keywords: r.System.Keywords, SystemTime: r.System.TimeCreated.SystemTime,
		EventRecordID: r.System.EventRecordID, Channel: r.System.Channel, Computer: r.System.Computer,
		UserID: r.System.Security.UserID,
	}
	for _, d := range r.EventData.Data {
		w.Data = append(w.Data, winData{Name: d.Name, Value: d.Value})
	}
	if m := refUserDataLeaves(r.UserData.Inner); len(m) > 0 {
		w.UserData = m
	}
	return w, nil
}

// refUserDataLeaves spłaszcza UserData do mapy nazwa-elementu → tekst.
func refUserDataLeaves(inner []byte) map[string]string {
	out := map[string]string{}
	if len(bytes.TrimSpace(inner)) == 0 {
		return out
	}
	type elem struct {
		name     string
		hasChild bool
	}
	dec := xml.NewDecoder(bytes.NewReader(inner))
	var stack []elem
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err != nil { // io.EOF lub błąd składni – zwracamy to, co udało się odczytać
			return out
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) > 0 {
				stack[len(stack)-1].hasChild = true
			}
			stack = append(stack, elem{name: t.Name.Local})
			text.Reset()
		case xml.CharData:
			text.Write(t)
		case xml.EndElement:
			if n := len(stack); n > 0 {
				if top := stack[n-1]; !top.hasChild {
					out[top.name] = strings.TrimSpace(text.String())
				}
				stack = stack[:n-1]
			}
			text.Reset()
		}
	}
}
