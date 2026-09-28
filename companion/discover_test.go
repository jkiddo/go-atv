package companion

import "testing"

func TestIsCompanionService(t *testing.T) {
	for _, name := range []string{
		"Living Room._companion-link._tcp.local.",
		"Living Room._COMPANION-LINK._TCP.LOCAL",
	} {
		if !isCompanionService(name) {
			t.Errorf("isCompanionService(%q) = false", name)
		}
	}
	if isCompanionService("badSeed._airplay._tcp.local.") {
		t.Error("accepted unrelated AirPlay service")
	}
}
