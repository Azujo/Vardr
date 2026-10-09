package chwriter

import (
	"context"
	"errors"

	"github.com/ClickHouse/clickhouse-go/v2"

	"siem/internal/model"
)

// dataError oznacza, że zapis odrzucono z powodu TREŚCI wierszy (nie
// awarii) – ponawianie tej samej paczki nic nie zmieni.
type dataError struct{ err error }

func (e *dataError) Error() string { return e.err.Error() }
func (e *dataError) Unwrap() error { return e.err }

// dataErrorCodes to kody wyjątków ClickHouse oznaczające złe dane.
// Lista jest celowo zachowawcza: nieznany kod traktujemy jak awarię
// (ponowienie), bo pomyłka w drugą stronę wysłałaby do kwarantanny
// poprawne zdarzenia, np. przy braku pamięci serwera.
var dataErrorCodes = map[int32]bool{
	6:   true, // CANNOT_PARSE_TEXT
	27:  true, // CANNOT_PARSE_INPUT_ASSERTION_FAILED
	38:  true, // CANNOT_PARSE_DATE
	41:  true, // CANNOT_PARSE_DATETIME
	53:  true, // TYPE_MISMATCH
	69:  true, // ARGUMENT_OUT_OF_BOUND
	70:  true, // CANNOT_CONVERT_TYPE
	72:  true, // CANNOT_PARSE_NUMBER
	117: true, // INCORRECT_DATA
	131: true, // TOO_LARGE_STRING_SIZE
	321: true, // VALUE_IS_OUT_OF_RANGE_OF_DATA_TYPE
	407: true, // DECIMAL_OVERFLOW
}

// IsDataError rozróżnia złe dane (szukamy złego wiersza) od awarii
// (ponawiamy całość).
func IsDataError(err error) bool {
	var de *dataError
	if errors.As(err, &de) {
		return true
	}
	var ex *clickhouse.Exception
	return errors.As(err, &ex) && dataErrorCodes[ex.Code]
}

// Rejected to zdarzenie, którego ClickHouse nie przyjął.
type Rejected struct {
	Event model.Event
	Err   error
}

// Quarantined zamienia odrzucone zdarzenie we wpis kwarantanny
// (oryginał zostaje zachowany – nic nie znika bez śladu).
func (r Rejected) Quarantined() model.Quarantined {
	return model.Quarantined{
		Ingested: r.Event.Ingested, AgentID: r.Event.AgentID, EventID: r.Event.ID,
		Source: r.Event.Dataset, Reason: "zapis do ClickHouse odrzucony: " + r.Err.Error(), Raw: r.Event.Raw,
		Peer: r.Event.Fields["syslog.peer"], Truncated: r.Event.Truncated,
	}
}

// Bisect zapisuje zdarzenia funkcją insert. Jeśli ClickHouse odrzuci
// paczkę z powodu danych, dzieli ją na połowy aż do pojedynczych złych
// wierszy – te zwraca jako Rejected, resztę zapisuje (ustalenie K2:
// jeden zły wiersz nie może zatrzymać całego potoku). Przy awarii
// przerywa i zwraca błąd; części już zapisane zgłasza przez ok (żeby
// nie zapisać ich drugi raz po ponownym dostarczeniu).
func Bisect(ctx context.Context, events []model.Event,
	insert func(context.Context, []model.Event) error, ok func([]model.Event)) ([]Rejected, error) {
	if len(events) == 0 {
		return nil, nil
	}
	err := insert(ctx, events)
	switch {
	case err == nil:
		ok(events)
		return nil, nil
	case !IsDataError(err):
		return nil, err
	case len(events) == 1:
		return []Rejected{{Event: events[0], Err: err}}, nil
	}
	mid := len(events) / 2
	left, err := Bisect(ctx, events[:mid], insert, ok)
	if err != nil {
		return left, err
	}
	right, err := Bisect(ctx, events[mid:], insert, ok)
	return append(left, right...), err
}
