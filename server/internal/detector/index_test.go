package detector

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2"
)

func TestResourceError(t *testing.T) {
	mem := fmt.Errorf("skan: %w", &clickhouse.Exception{Code: 241, Message: "memory limit exceeded"})
	regex := fmt.Errorf("skan: %w", &clickhouse.Exception{Code: 427, Message: "cannot compile regexp"})
	if !resourceError(mem) || resourceError(regex) || !resourceError(errors.New("connection reset")) {
		t.Fatal("klasyfikacja błędów ClickHouse")
	}
}
