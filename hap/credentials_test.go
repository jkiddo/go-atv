package hap

import "testing"

func TestLegacyCredentialsRoundTrip(t *testing.T) {
	original := Credentials{
		ClientID: []byte{0x75, 0xfb, 0xee, 0xc7, 0x73, 0xcf, 0xc5, 0x63},
		LTSK:     make([]byte, 32),
	}
	encoded := original.String()
	if encoded != "75fbeec773cfc563:0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("String() = %q", encoded)
	}
	parsed, err := ParseCredentials(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.IsLegacy() || parsed.IsHAP() {
		t.Fatalf("parsed credentials type = %#v", parsed)
	}
	if parsed.String() != encoded {
		t.Fatalf("round trip = %q, want %q", parsed.String(), encoded)
	}
}
