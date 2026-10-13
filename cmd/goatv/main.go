// Command goatv is a small CLI for the goatv Companion library: discover
// Apple TVs, pair with them and control/observe power state.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jkiddo/go-atv/airplay"
	"github.com/jkiddo/go-atv/companion"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: goatv <command> [flags]

Commands:
  scan                     Discover Apple TVs on the network
  pair                     Pair with an Apple TV (PIN shown on the TV)
  status                   Print current power state and exit
  watch                    Stream power/availability state as JSON lines
  button <name>            Press a remote button (up, down, select, menu, ...)
  wake | sleep             Turn the Apple TV on or off
  apps                     List launchable apps
  launch <bundle-id>       Launch an app
  pair-airplay             Pair for AirPlay streaming (PIN shown on the TV)
  play <url|file>          Stream a video URL or local file via AirPlay

Flags (for all commands except scan):
  -host <ip>               Device address (skips discovery)
  -name <device name>      Device name to match during discovery
  -credentials <file>      Credentials file (default ~/.goatv/credentials)
  -airplay-credentials <file>
                           AirPlay credentials file (default ~/.goatv/credentials-airplay)
  -client-name <name>      Name shown on the Apple TV (default "goatv")
  -timeout <duration>      Discovery timeout (default 5s)
  -fairplay-control       Opt into experimental legacy fp-setup2 video
  -position <seconds>      Start position for play (default 0)
`)
	os.Exit(2)
}

func run() error {
	if len(os.Args) < 2 {
		usage()
	}
	command := os.Args[1]

	flags := flag.NewFlagSet(command, flag.ExitOnError)
	host := flags.String("host", "", "device address")
	deviceName := flags.String("name", "", "device name to match during discovery")
	credentials := flags.String("credentials", defaultCredentialsPath(), "credentials file")
	airplayCredentials := flags.String("airplay-credentials", defaultCredentialsPath()+"-airplay", "AirPlay credentials file")
	clientName := flags.String("client-name", "goatv", "client name shown on the Apple TV")
	timeout := flags.Duration("timeout", 5*time.Second, "discovery timeout")
	fairPlay := flags.Bool("fairplay-control", false, "experimental legacy fp-setup2 video")
	position := flags.Float64("position", 0, "start position in seconds for play")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if command == "scan" {
		return scan(ctx, *timeout)
	}

	if command == "pair-airplay" || command == "play" {
		client, err := airplayClient(ctx, *host, *deviceName, *clientName, *airplayCredentials, *timeout, airplay.WithFairPlayControl(*fairPlay))
		if err != nil {
			return err
		}
		if command == "pair-airplay" {
			return pairAirPlay(ctx, client)
		}
		if flags.NArg() < 1 {
			return fmt.Errorf("usage: goatv play <url|file>")
		}
		err = client.PlayURL(ctx, flags.Arg(0), *position)
		if errors.Is(err, context.Canceled) {
			return nil // interrupted by the user
		}
		return err
	}

	addr, port, err := resolveDevice(ctx, *host, *deviceName, *timeout)
	if err != nil {
		return err
	}
	client := companion.New(*clientName, *credentials, addr, companion.WithPort(port))

	switch command {
	case "pair":
		return pair(ctx, client, addr)
	case "status":
		return status(ctx, client)
	case "watch":
		return watch(ctx, client)
	case "button":
		if flags.NArg() < 1 {
			return fmt.Errorf("usage: goatv button <name>")
		}
		return button(ctx, client, flags.Arg(0))
	case "wake":
		return withConnection(ctx, client, client.Wake)
	case "sleep":
		return withConnection(ctx, client, client.Sleep)
	case "apps":
		return apps(ctx, client)
	case "launch":
		if flags.NArg() < 1 {
			return fmt.Errorf("usage: goatv launch <bundle-id>")
		}
		return withConnection(ctx, client, func(ctx context.Context) error {
			return client.LaunchApp(ctx, flags.Arg(0))
		})
	default:
		usage()
		return nil
	}
}

// airplayClient resolves an AirPlay receiver (via -host or discovery) and
// returns a client for it.
func airplayClient(ctx context.Context, host, name, clientName, credentials string, timeout time.Duration, extra ...airplay.Option) (*airplay.Client, error) {
	if host != "" {
		return airplay.New(clientName, credentials, host, extra...), nil
	}
	devices, err := airplay.Discover(ctx, timeout)
	if err != nil {
		return nil, err
	}
	if name != "" {
		for _, device := range devices {
			if strings.EqualFold(device.Name, name) {
				return airplay.New(clientName, credentials, device.IP,
					append(append([]airplay.Option(nil), extra...), airplay.WithPort(device.Port), airplay.WithProperties(device.Properties))...), nil
			}
		}
		var names []string
		for _, device := range devices {
			names = append(names, fmt.Sprintf("%s (%s)", device.Name, device.IP))
		}
		sort.Strings(names)
		return nil, fmt.Errorf("device %q not found; discovered: %s", name, strings.Join(names, ", "))
	}
	if len(devices) == 1 {
		device := devices[0]
		return airplay.New(clientName, credentials, device.IP,
			append(append([]airplay.Option(nil), extra...), airplay.WithPort(device.Port), airplay.WithProperties(device.Properties))...), nil
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("no AirPlay devices found; specify -host")
	}
	var names []string
	for _, device := range devices {
		names = append(names, device.Name)
	}
	return nil, fmt.Errorf("multiple devices found (%s); use -name or -host", strings.Join(names, ", "))
}

func pairAirPlay(ctx context.Context, client *airplay.Client) error {
	fmt.Println("Pairing for AirPlay — a PIN will appear on the TV")
	if err := client.StartPairing(ctx); err != nil {
		return fmt.Errorf("start pairing: %w", err)
	}
	defer client.CancelPairing()
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the PIN shown on the TV: ")
	pin, err := reader.ReadString('\n')
	if err != nil && pin == "" {
		return fmt.Errorf("read PIN: %w", err)
	}
	if err := client.FinishPairing(ctx, strings.TrimSpace(pin)); err != nil {
		return fmt.Errorf("finish pairing: %w", err)
	}
	required, err := client.StartPasswordPairing(ctx)
	if err != nil {
		return fmt.Errorf("start AirPlay code authentication: %w", err)
	}
	if required {
		fmt.Print("Enter the AirPlay code now shown on the TV: ")
		code, readErr := reader.ReadString('\n')
		if readErr != nil && code == "" {
			return fmt.Errorf("read AirPlay code: %w", readErr)
		}
		if err := client.FinishPasswordPairing(ctx, strings.TrimSpace(code)); err != nil {
			return fmt.Errorf("finish AirPlay code authentication: %w", err)
		}
	}
	fmt.Println("Paired. Credentials saved.")
	return nil
}

func defaultCredentialsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "goatv-credentials"
	}
	return home + "/.goatv/credentials"
}

func scan(ctx context.Context, timeout time.Duration) error {
	// hashicorp/mdns does not reliably support simultaneous queries on all
	// platforms, so browse the two services one after the other.
	companionDevices, companionErr := companion.Discover(ctx, timeout)
	airplayDevices, airplayErr := airplay.Discover(ctx, timeout)
	if companionErr != nil && airplayErr != nil {
		return errors.Join(companionErr, airplayErr)
	}
	if companionErr != nil {
		fmt.Fprintln(os.Stderr, "warning: Companion discovery failed:", companionErr)
	}
	if airplayErr != nil {
		fmt.Fprintln(os.Stderr, "warning: AirPlay discovery failed:", airplayErr)
	}

	devices := mergeDiscoveredDevices(companionDevices, airplayDevices)
	if len(devices) == 0 {
		fmt.Println("No Apple TV or AirPlay devices found")
		return nil
	}
	for _, device := range devices {
		fmt.Printf("%-30s %-15s %-30s (%s)\n", device.Name, device.IP, device.protocols(), device.model())
	}
	return nil
}

type discoveredDevice struct {
	Name          string
	IP            string
	Model         string
	CompanionPort int
	AirPlayPort   int
}

func mergeDiscoveredDevices(companionDevices []companion.Device, airplayDevices []airplay.Device) []discoveredDevice {
	byIP := make(map[string]*discoveredDevice)
	for _, device := range companionDevices {
		merged := &discoveredDevice{
			Name:          device.Name,
			IP:            device.IP,
			Model:         device.Model,
			CompanionPort: device.Port,
		}
		byIP[device.IP] = merged
	}
	for _, device := range airplayDevices {
		merged := byIP[device.IP]
		if merged == nil {
			merged = &discoveredDevice{IP: device.IP}
			byIP[device.IP] = merged
		}
		if merged.Name == "" {
			merged.Name = device.Name
		}
		if merged.Model == "" {
			merged.Model = device.Model()
		}
		merged.AirPlayPort = device.Port
	}

	devices := make([]discoveredDevice, 0, len(byIP))
	for _, device := range byIP {
		devices = append(devices, *device)
	}
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].Name == devices[j].Name {
			return devices[i].IP < devices[j].IP
		}
		return devices[i].Name < devices[j].Name
	})
	return devices
}

func (d discoveredDevice) protocols() string {
	var protocols []string
	if d.CompanionPort != 0 {
		protocols = append(protocols, fmt.Sprintf("companion:%d", d.CompanionPort))
	}
	if d.AirPlayPort != 0 {
		protocols = append(protocols, fmt.Sprintf("airplay:%d", d.AirPlayPort))
	}
	return strings.Join(protocols, ", ")
}

func (d discoveredDevice) model() string {
	if d.Model == "" {
		return "unknown model"
	}
	return d.Model
}

func resolveDevice(ctx context.Context, host, name string, timeout time.Duration) (string, int, error) {
	if host != "" {
		return host, 0, nil
	}
	devices, err := companion.Discover(ctx, timeout)
	if err != nil {
		return "", 0, err
	}
	if name != "" {
		for _, device := range devices {
			if strings.EqualFold(device.Name, name) {
				return device.IP, device.Port, nil
			}
		}
		var names []string
		for _, device := range devices {
			names = append(names, fmt.Sprintf("%s (%s)", device.Name, device.IP))
		}
		sort.Strings(names)
		return "", 0, fmt.Errorf("device %q not found; discovered: %s", name, strings.Join(names, ", "))
	}
	if len(devices) == 1 {
		return devices[0].IP, devices[0].Port, nil
	}
	if len(devices) == 0 {
		return "", 0, fmt.Errorf("no Companion devices found; specify -host")
	}
	var names []string
	for _, device := range devices {
		names = append(names, device.Name)
	}
	return "", 0, fmt.Errorf("multiple devices found (%s); use -name or -host", strings.Join(names, ", "))
}

func pair(ctx context.Context, client *companion.Client, addr string) error {
	fmt.Printf("Pairing with Apple TV at %s — a PIN will appear on the TV\n", addr)
	if err := client.StartPairing(ctx); err != nil {
		return fmt.Errorf("start pairing: %w", err)
	}
	fmt.Print("Enter the PIN shown on the TV: ")
	pin, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && pin == "" {
		return fmt.Errorf("read PIN: %w", err)
	}
	if err := client.FinishPairing(ctx, strings.TrimSpace(pin)); err != nil {
		return fmt.Errorf("finish pairing: %w", err)
	}
	fmt.Println("Paired. Credentials saved.")
	return nil
}

func withConnection(ctx context.Context, client *companion.Client, fn func(context.Context) error) error {
	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err := client.Connect(connectCtx)
	cancel()
	if err != nil {
		return err
	}
	defer client.Disconnect()
	return fn(ctx)
}

func status(ctx context.Context, client *companion.Client) error {
	return withConnection(ctx, client, func(context.Context) error {
		// Give a pushed status event a moment to arrive if the initial
		// fetch was not supported by this tvOS version.
		deadline := time.Now().Add(3 * time.Second)
		for {
			if state, known := client.PowerState(); known {
				fmt.Println(state)
				return nil
			}
			if time.Now().After(deadline) {
				fmt.Println(companion.PowerStateUnknown)
				return nil
			}
			time.Sleep(200 * time.Millisecond)
		}
	})
}

type watchState struct {
	Available *bool  `json:"available,omitempty"`
	On        *bool  `json:"on,omitempty"`
	State     string `json:"state,omitempty"`
	UpdatedAt int64  `json:"updated_at"`
}

func watch(ctx context.Context, client *companion.Client) error {
	encoder := json.NewEncoder(os.Stdout)
	emit := func(update func(*watchState)) {
		state := watchState{UpdatedAt: time.Now().Unix()}
		update(&state)
		_ = encoder.Encode(state)
	}

	client.AddIsAvailableUpdatedCallback(func(available bool) {
		emit(func(s *watchState) { s.Available = &available })
	})
	client.AddPowerStateUpdatedCallback(func(state companion.PowerState) {
		on := state == companion.PowerStateOn
		emit(func(s *watchState) {
			s.On = &on
			s.State = state.String()
		})
	})

	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err := client.Connect(connectCtx)
	cancel()
	if err != nil {
		return err
	}
	defer client.Disconnect()

	invalidAuth := make(chan struct{}, 1)
	client.KeepReconnecting(func() {
		select {
		case invalidAuth <- struct{}{}:
		default:
		}
	})

	select {
	case <-ctx.Done():
		return nil
	case <-invalidAuth:
		return fmt.Errorf("Apple TV rejected the credentials; run goatv pair again")
	}
}

func button(ctx context.Context, client *companion.Client, name string) error {
	command, ok := companion.HidCommandNames[strings.ToLower(name)]
	if !ok {
		var names []string
		for n := range companion.HidCommandNames {
			names = append(names, n)
		}
		sort.Strings(names)
		return fmt.Errorf("unknown button %q; valid: %s", name, strings.Join(names, ", "))
	}
	return withConnection(ctx, client, func(ctx context.Context) error {
		return client.PressButton(ctx, command)
	})
}

func apps(ctx context.Context, client *companion.Client) error {
	return withConnection(ctx, client, func(ctx context.Context) error {
		appMap, err := client.AppList(ctx)
		if err != nil {
			return err
		}
		type app struct{ name, bundleID string }
		var list []app
		for bundleID, name := range appMap {
			list = append(list, app{name, bundleID})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].name < list[j].name })
		for _, a := range list {
			fmt.Printf("%-40s %s\n", a.name, a.bundleID)
		}
		return nil
	})
}
