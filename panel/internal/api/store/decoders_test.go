package store

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestPostgresDecoders(t *testing.T) {
	url := os.Getenv("SIEM_TEST_PG_URL")
	if url == "" {
		t.Skip("brak SIEM_TEST_PG_URL – pomijam test na PostgreSQL")
	}
	ctx := context.Background()
	db, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.pool.Exec(ctx, "TRUNCATE syslog_decoders, syslog_decoder_versions"); err != nil {
		t.Fatal(err)
	}
	d, err := db.SaveDecoder(ctx, SyslogDecoder{ID: "nas", Source: "id: nas", Enabled: true, UpdatedBy: "adam"}, "saved", "pierwsza")
	if err != nil || d.Revision != 1 {
		t.Fatalf("zapis: %+v %v", d, err)
	}
	if d, err = db.SaveDecoder(ctx, SyslogDecoder{ID: "nas", Source: "id: nas", Enabled: false, UpdatedBy: "ola"}, "disabled", "szum"); err != nil || d.Revision != 2 {
		t.Fatalf("zmiana: %+v %v", d, err)
	}
	if _, err := db.SaveDecoder(ctx, SyslogDecoder{ID: "Zła Nazwa", UpdatedBy: "x"}, "saved", ""); err == nil {
		t.Fatal("baza powinna odrzucić niepoprawny id")
	}
	if _, err := db.DeleteDecoder(ctx, "nas", "cofnięcie", "adam"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DeleteDecoder(ctx, "nas", "", "adam"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("drugie usunięcie: %v", err)
	}
	// Ponowny zapis po cofnięciu – rewizja rośnie dalej.
	if d, err = db.SaveDecoder(ctx, SyslogDecoder{ID: "nas", Source: "id: nas", Enabled: true, UpdatedBy: "adam"}, "saved", ""); err != nil || d.Revision != 4 {
		t.Fatalf("ponowny zapis: %+v %v", d, err)
	}
	vs, err := db.DecoderVersions(ctx, "nas", 10)
	if err != nil || len(vs) != 4 || vs[0].Revision != 4 || vs[1].Action != "reverted" || vs[2].ChangedBy != "ola" {
		t.Fatalf("historia: %+v %v", vs, err)
	}
	list, err := db.ListDecoders(ctx)
	if err != nil || len(list) != 1 || !list[0].Enabled {
		t.Fatalf("lista: %+v %v", list, err)
	}
}
