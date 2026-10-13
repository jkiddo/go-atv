package simulator

import (
	"net"
	"strings"
	"testing"

	"github.com/hashicorp/mdns"
	"github.com/miekg/dns"
)

func TestFairPlayDiscoveryPublishesBothServices(t *testing.T) {
	r, err := New(Config{FairPlay: true, Name: "Lab receiver", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	services := r.discoveryServices()
	if len(services) != 2 {
		t.Fatal("missing RAOP advertisement")
	}
	var zone discoveryZone
	for _, s := range services {
		entry, err := mdns.NewMDNSService(s.name, s.kind, "local.", "lab.local.", r.Port(), []net.IP{net.IPv4(192, 0, 2, 1)}, s.txt)
		if err != nil {
			t.Fatal(err)
		}
		zone = append(zone, entry)
		txt := map[string]string{}
		for _, v := range s.txt {
			k, v, _ := strings.Cut(v, "=")
			txt[k] = v
		}
		if txt["pk"] == "" || txt["pi"] == "" || txt["pw"] != "true" {
			t.Fatalf("missing shared identity/security TXT")
		}
		args := nativeBonjourArgs(s, "en0", "lab.local", "192.0.2.1", r.Port())
		if args[0] != "-i" || args[1] != "en0" || args[2] != "-P" || args[4] != s.kind {
			t.Fatalf("native args: %v", args)
		}
	}
	for _, kind := range []string{"_airplay._tcp.local.", "_raop._tcp.local."} {
		records := zone.Records(dns.Question{Name: kind, Qtype: dns.TypePTR, Qclass: dns.ClassINET})
		found := false
		for _, rr := range records {
			if ptr, ok := rr.(*dns.PTR); ok && ptr.Hdr.Name == kind {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing PTR for %s", kind)
		}
	}
}
func TestDiscoveryConfigurationRejectsInvalidBackend(t *testing.T) {
	if r, err := New(Config{DiscoveryBackend: "typo"}); err == nil {
		r.Close()
		t.Fatal("invalid discovery backend accepted")
	}
}
