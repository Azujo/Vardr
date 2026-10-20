package contract

import (
	"os"
	"strings"
	"testing"
)

// Wypełniacze w definicji instalatora muszą być dokładnie takie jak tu –
// inaczej panel nie wpisze adresu i tokenu do pobieranego MSI.
func TestMSIPlaceholdersInWxs(t *testing.T) {
	wxs, err := os.ReadFile("../../deploy/lab/msi/agent.wxs")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{MSIServerPlaceholder, MSITokenPlaceholder} {
		if !strings.Contains(string(wxs), `Value="`+p+`"`) {
			t.Errorf("agent.wxs nie ma wypełniacza %.24s…", p)
		}
	}
	if MSIValue(MSIServerPlaceholder) != "" || MSIValue("192.168.88.98      ") != "192.168.88.98" || MSIValue("") != "" {
		t.Fatal("MSIValue")
	}
}

// Wypełniacz instalatora sprzed zmiany nazwy na Vardr nadal oznacza „brak wartości”.
func TestMSIValueLegacyPlaceholder(t *testing.T) {
	if MSIValue("HEIMDALL_MSI_SERVER_"+strings.Repeat("=", 108)) != "" || len(MSIServerPlaceholder) != 128 || len(MSITokenPlaceholder) != 64 {
		t.Fatal("dawny wypełniacz")
	}
}
