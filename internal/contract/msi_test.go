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
