package companion

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

// serviceType is the mDNS service announced by Companion-capable devices.
const serviceType = "_companion-link._tcp"

// Device is an Apple TV (or other Companion device) found on the network.
type Device struct {
	Name  string // instance name, e.g. "Living Room"
	IP    string
	Port  int
	Model string // rpmd property, e.g. "AppleTV11,1" (may be empty)
}

// Discover browses the local network for Companion devices.
func Discover(ctx context.Context, timeout time.Duration) ([]Device, error) {
	entries := make(chan *mdns.ServiceEntry, 32)
	done := make(chan struct{})

	var devices []Device
	seen := make(map[string]bool)
	go func() {
		defer close(done)
		for entry := range entries {
			if !isCompanionService(entry.Name) {
				continue
			}
			device := entryToDevice(entry)
			if device.IP == "" || seen[device.IP+device.Name] {
				continue
			}
			seen[device.IP+device.Name] = true
			devices = append(devices, device)
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

	sort.Slice(devices, func(i, j int) bool { return devices[i].Name < devices[j].Name })
	return devices, nil
}

func isCompanionService(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return strings.HasSuffix(name, "."+serviceType+".local")
}

func entryToDevice(entry *mdns.ServiceEntry) Device {
	device := Device{Port: entry.Port}
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
		if value, ok := strings.CutPrefix(field, "rpmd="); ok {
			device.Model = value
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
