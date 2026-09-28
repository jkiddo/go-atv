package simulator_test

import (
	"context"
	"fmt"
	"github.com/jkiddo/go-atv/airplay"
	"github.com/jkiddo/go-atv/simulator"
	"os"
	"testing"
	"time"
)

// Opt-in: regular test runs remain isolated from LAN multicast.
func TestMDNSDiscovery(t *testing.T) {
	ip := os.Getenv("SIMULATOR_MDNS_IP")
	if ip == "" {
		t.Skip("set SIMULATOR_MDNS_IP to this machine's LAN IPv4 address")
	}
	name := fmt.Sprintf("Simulator Test %d", time.Now().UnixNano())
	r, err := simulator.New(simulator.Config{Listen: "0.0.0.0:0", Name: name, AdvertiseIP: ip})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	devices, err := airplay.Discover(ctx, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range devices {
		if device.Name == name && device.Port == r.Port() && device.IP == ip {
			return
		}
	}
	t.Fatalf("simulator was not discovered: %v", devices)
}
