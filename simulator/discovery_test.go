package simulator_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/mdns"
	"github.com/jkiddo/go-atv/airplay"
	"github.com/jkiddo/go-atv/simulator"
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

func TestFairPlayMDNSDiscovery(t *testing.T) {
	ip := os.Getenv("SIMULATOR_MDNS_IP")
	if ip == "" {
		t.Skip("set SIMULATOR_MDNS_IP for LAN discovery test")
	}
	for _, backend := range []string{"auto", "go"} {
		t.Run(backend, func(t *testing.T) {
			name := fmt.Sprintf("FP Discovery %d", time.Now().UnixNano())
			r, err := simulator.New(simulator.Config{Listen: net.JoinHostPort(ip, "0"), Name: name, AdvertiseIP: ip, FairPlay: true, DiscoveryBackend: backend})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			for _, kind := range []string{"_airplay._tcp", "_raop._tcp"} {
				entries := make(chan *mdns.ServiceEntry, 64)
				params := mdns.DefaultParams(kind)
				params.Timeout = 2 * time.Second
				params.Entries = entries
				params.DisableIPv6 = true
				params.Logger = log.New(io.Discard, "", 0)
				result := make(chan []*mdns.ServiceEntry, 1)
				go func() {
					var collected []*mdns.ServiceEntry
					for entry := range entries {
						// mdns mutates emitted entries while the query is running.
						// Drain pointers now and inspect fields only after it returns.
						collected = append(collected, entry)
					}
					result <- collected
				}()
				err := mdns.Query(params)
				close(entries)
				collected := <-result
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, entry := range collected {
					// Match the unique listening port: DNS presentation names escape spaces.
					if entry.Port == r.Port() && entry.AddrV4.String() == ip {
						found = true
					}
				}
				if !found {
					t.Fatalf("%s not discovered via %s", kind, backend)
				}
			}
		})
	}
}
