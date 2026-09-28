package airplay

import (
	"context"
	"io"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
)

// serviceType is the mDNS service announced by AirPlay receivers.
const serviceType = "_airplay._tcp"

// Device is an AirPlay receiver found on the network.
type Device struct {
	Name       string // instance name, e.g. "Living Room"
	IP         string
	Port       int
	Properties map[string]string // TXT record properties (features, model, ...)
}

// Model returns the model TXT property, e.g. "AppleTV11,1" (may be empty).
func (d Device) Model() string { return d.Properties["model"] }

// Discover browses the local network for AirPlay receivers.
func Discover(ctx context.Context, timeout time.Duration) ([]Device, error) {
	entries := make(chan *mdns.ServiceEntry, 32)
	done := make(chan struct{})

	// mdns reuses and updates entry pointers while processing later records.
	// Collect pointers now, but only inspect them after QueryContext returns.
	var collected []*mdns.ServiceEntry
	go func() {
		defer close(done)
		for entry := range entries {
			collected = append(collected, entry)
		}
	}()

	params := &mdns.QueryParam{
		Service:             serviceType,
		Domain:              "local",
		Timeout:             timeout,
		Entries:             entries,
		DisableIPv6:         true,
		WantUnicastResponse: true,
		// The library logs a warning when IPv6 listening fails, which is
		// expected since IPv6 is disabled above.
		Logger: log.New(io.Discard, "", 0),
	}
	err := mdns.QueryContext(ctx, params)
	close(entries)
	<-done
	if err != nil && ctx.Err() == nil {
		return nil, err
	}

	var devices []Device
	seen := make(map[string]bool)
	for _, entry := range collected {
		if !isAirPlayService(entry.Name) {
			continue
		}
		device := entryToDevice(entry)
		if device.IP == "" || seen[device.IP+device.Name] {
			continue
		}
		seen[device.IP+device.Name] = true
		devices = append(devices, device)
	}

	sort.Slice(devices, func(i, j int) bool { return devices[i].Name < devices[j].Name })
	return devices, nil
}

func isAirPlayService(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return strings.HasSuffix(name, "."+serviceType+".local")
}

func entryToDevice(entry *mdns.ServiceEntry) Device {
	device := Device{Port: entry.Port, Properties: make(map[string]string)}
	if entry.AddrV4 != nil {
		device.IP = entry.AddrV4.String()
	} else if entry.Addr != nil {
		device.IP = entry.Addr.String()
	}

	name := entry.Name
	if idx := strings.Index(name, "."+serviceType); idx >= 0 {
		name = name[:idx]
	}
	device.Name = unescapeDNS(name)

	for _, field := range entry.InfoFields {
		if key, value, found := strings.Cut(field, "="); found {
			device.Properties[key] = value
		}
	}
	return device
}

// unescapeDNS reverses the escaping applied to DNS instance names
// (\. \\ and \DDD decimal escapes).
func unescapeDNS(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 < len(s) && isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]) {
			code, err := strconv.Atoi(s[i+1 : i+4])
			if err == nil && code < 256 {
				b.WriteByte(byte(code))
				i += 3
				continue
			}
		}
		if i+1 < len(s) {
			b.WriteByte(s[i+1])
			i++
		}
	}
	return b.String()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
