package simulator

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
	"github.com/miekg/dns"
)

type discoveryService struct {
	name, kind string
	txt        []string
}

func (r *Receiver) discoveryServices() []discoveryService {
	services := []discoveryService{{r.config.Name, "_airplay._tcp", r.TXTRecords()}}
	if !r.config.FairPlay {
		return services
	}
	fields := map[string]string{}
	for _, s := range r.TXTRecords() {
		k, v, _ := strings.Cut(s, "=")
		fields[k] = v
	}
	raop := []string{"ch=2", "cn=0,1,2,3", "et=0,3,5", "md=0,1,2", "pw=" + fields["pw"], "sr=44100", "ss=16", "tp=UDP", "sv=false", "da=true", "vn=65537", "vs=220.68", "am=AppleTV3,2", "sf=" + fields["flags"], "ft=" + fields["features"], "pk=" + fields["pk"], "pi=" + fields["pi"], "vv=2", "txtvers=1"}
	return append(services, discoveryService{strings.ReplaceAll(fields["deviceid"], ":", "") + "@" + r.config.Name, "_raop._tcp", raop})
}

type discoveryZone []*mdns.MDNSService

func (z discoveryZone) Records(q dns.Question) []dns.RR {
	var records []dns.RR
	seen := map[string]bool{}
	for _, service := range z {
		for _, rr := range service.Records(q) {
			if !seen[rr.String()] {
				records = append(records, rr)
				seen[rr.String()] = true
			}
		}
	}
	return records
}
func (r *Receiver) advertise(ip net.IP) error {
	iface, err := interfaceForIP(ip)
	if err != nil {
		return err
	}
	backend := r.config.DiscoveryBackend
	if backend == "native" || ((backend == "" || backend == "auto") && runtime.GOOS == "darwin" && r.config.FairPlay) {
		return r.advertiseNative(ip, iface)
	}
	var zone discoveryZone
	for _, service := range r.discoveryServices() {
		entry, err := mdns.NewMDNSService(service.name, service.kind, "local.", "airplay-sim-"+r.id[:12]+".local.", r.Port(), []net.IP{ip}, service.txt)
		if err != nil {
			return err
		}
		zone = append(zone, entry)
	}
	server, err := mdns.NewServer(&mdns.Config{Zone: zone, Iface: iface, Logger: log.New(io.Discard, "", 0)})
	if err == nil {
		r.shutdownDiscovery = func() { server.Shutdown() }
	}
	return err
}

type bonjourChild struct {
	cmd  *exec.Cmd
	done chan error
}

func nativeBonjourArgs(service discoveryService, iface, host, ip string, port int) []string {
	args := []string{"-i", iface, "-P", service.name, service.kind, "local", strconv.Itoa(port), host, ip}
	return append(args, service.txt...)
}
func (r *Receiver) advertiseNative(ip net.IP, iface *net.Interface) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("native Bonjour backend requires macOS; use go backend")
	}
	var children []bonjourChild
	stop := func() {
		for _, child := range children {
			child.cmd.Process.Signal(os.Interrupt)
		}
		for _, child := range children {
			select {
			case <-child.done:
			case <-time.After(2 * time.Second):
				child.cmd.Process.Kill()
				<-child.done
			}
		}
	}
	for _, service := range r.discoveryServices() {
		cmd := exec.Command("/usr/bin/dns-sd", nativeBonjourArgs(service, iface.Name, "airplay-sim-"+r.id[:12]+".local", ip.String(), r.Port())...)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			stop()
			return fmt.Errorf("start Bonjour registration: %w", err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait(); close(done) }()
		children = append(children, bonjourChild{cmd, done})
		select {
		case err := <-done:
			stop()
			return fmt.Errorf("Bonjour registration exited: %v", err)
		case <-time.After(150 * time.Millisecond):
		}
	}
	r.shutdownDiscovery = stop
	return nil
}
