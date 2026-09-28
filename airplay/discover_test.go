package airplay

import "testing"

func TestIsAirPlayService(t *testing.T) {
	for _, name := range []string{
		"Apple TV._airplay._tcp.local.",
		"Apple TV._AIRPLAY._TCP.LOCAL",
	} {
		if !isAirPlayService(name) {
			t.Errorf("isAirPlayService(%q) = false", name)
		}
	}
	if isAirPlayService("LuLu's._androidtvremote2._tcp.local.") {
		t.Error("accepted unrelated Android TV service")
	}
}
