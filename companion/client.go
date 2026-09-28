package companion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/jkiddo/go-atv/hap"
)

// DefaultPort is the Companion port commonly used by Apple TV. The actual
// port is announced via mDNS (_companion-link._tcp) and should normally be
// taken from discovery.
const DefaultPort = 49153

// Client is a high-level Companion client for a single Apple TV: create,
// register callbacks, Connect, optionally KeepReconnecting.
type Client struct {
	name            string
	credentialsFile string
	host            string
	port            int

	mu           sync.Mutex
	session      *session
	credentials  *hap.Credentials
	powerState   PowerState
	powerKnown   bool
	available    bool
	sid          int64
	reconnecting bool
	stopped      bool

	powerCallbacks     []func(PowerState)
	isOnCallbacks      []func(bool)
	availableCallbacks []func(bool)
	invalidAuth        func()

	pairing *pairSetup
}

// Option configures a Client.
type Option func(*Client)

// WithPort sets the Companion port (from mDNS discovery).
func WithPort(port int) Option {
	return func(c *Client) {
		if port > 0 {
			c.port = port
		}
	}
}

// New creates a client for host. clientName is the name shown on the Apple
// TV during pairing; credentialsFile stores pairing credentials in pyatv's
// format.
func New(clientName, credentialsFile, host string, opts ...Option) *Client {
	c := &Client{
		name:            clientName,
		credentialsFile: credentialsFile,
		host:            host,
		port:            DefaultPort,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// HasCredentials reports whether a credentials file exists and parses.
func (c *Client) HasCredentials() bool {
	_, err := hap.LoadCredentials(c.credentialsFile)
	return err == nil
}

// AddPowerStateUpdatedCallback registers a callback fired on power state
// changes.
func (c *Client) AddPowerStateUpdatedCallback(cb func(PowerState)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.powerCallbacks = append(c.powerCallbacks, cb)
}

// AddIsOnUpdatedCallback registers a callback fired when the on/off state
// changes.
func (c *Client) AddIsOnUpdatedCallback(cb func(bool)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isOnCallbacks = append(c.isOnCallbacks, cb)
}

// AddIsAvailableUpdatedCallback registers a callback fired when connection
// availability changes.
func (c *Client) AddIsAvailableUpdatedCallback(cb func(bool)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.availableCallbacks = append(c.availableCallbacks, cb)
}

// IsOn returns the current on/off state and whether it is known.
func (c *Client) IsOn() (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.powerState == PowerStateOn, c.powerKnown && c.powerState != PowerStateUnknown
}

// PowerState returns the current power state and whether it is known.
func (c *Client) PowerState() (PowerState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.powerState, c.powerKnown
}

// Connect loads credentials, connects, verifies and starts state tracking.
func (c *Client) Connect(ctx context.Context) error {
	credentials, err := hap.LoadCredentials(c.credentialsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("companion: no credentials at %s (pair first): %w", c.credentialsFile, err)
		}
		return err
	}

	c.mu.Lock()
	c.credentials = &credentials
	c.stopped = false
	c.mu.Unlock()

	return c.connectOnce(ctx)
}

func (c *Client) connectOnce(ctx context.Context) error {
	c.mu.Lock()
	credentials := c.credentials
	c.mu.Unlock()
	if credentials == nil {
		return errors.New("companion: not configured with credentials")
	}

	s, err := dialSession(ctx, c.host, c.port)
	if err != nil {
		return err
	}

	outputKey, inputKey, err := pairVerify(ctx, s, *credentials)
	if err != nil {
		s.close(nil)
		return err
	}
	if err := s.enableEncryption(outputKey, inputKey); err != nil {
		s.close(nil)
		return err
	}

	s.mu.Lock()
	s.onEvent = c.handleEvent
	s.mu.Unlock()

	if err := c.startSession(ctx, s, *credentials); err != nil {
		s.close(nil)
		return err
	}

	s.mu.Lock()
	s.onClose = c.handleConnectionLost
	s.mu.Unlock()

	c.mu.Lock()
	c.session = s
	c.mu.Unlock()
	c.setAvailable(true)
	return nil
}

// startSession performs the post-verify handshake: system info, session
// start and power-state subscriptions (pyatv's connect flow, minus touch and
// text input which this port does not need).
func (c *Client) startSession(ctx context.Context, s *session, credentials hap.Credentials) error {
	digest := sha256.Sum256(credentials.ClientID)
	rpID := hex.EncodeToString(digest[:6])
	pubID := fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		digest[0]|0x02, digest[1], digest[2], digest[3], digest[4], digest[5])

	infoCtx, cancel := withDefaultTimeout(ctx)
	_, err := s.exchangeOpack(infoCtx, "_systemInfo", map[string]any{
		"_bf":    int64(0),
		"_cf":    int64(512),
		"_clFl":  int64(128),
		"_i":     rpID, // a null "_i" stops the device from pushing power state events
		"_idsID": string(credentials.ClientID),
		"_pubID": pubID,
		"_sf":    int64(256),
		"_sv":    "170.18",
		"model":  "iPhone10,6",
		"name":   c.name,
	})
	cancel()
	if err != nil {
		return fmt.Errorf("companion: system info exchange: %w", err)
	}

	localSID := rand.Int63n(1 << 32)
	sessionCtx, cancel := withDefaultTimeout(ctx)
	resp, err := s.exchangeOpack(sessionCtx, "_sessionStart", map[string]any{
		"_srvT": "com.apple.tvremoteservices",
		"_sid":  localSID,
	})
	cancel()
	if err != nil {
		return fmt.Errorf("companion: session start: %w", err)
	}
	if content, ok := resp["_c"].(map[string]any); ok {
		if remoteSID, ok := content["_sid"].(int64); ok {
			c.mu.Lock()
			c.sid = remoteSID<<32 | localSID
			c.mu.Unlock()
		}
	}

	// tvOS only answers FetchAttentionState once a TV Remote Client session
	// is registered; older versions do not support this and that is fine.
	rcCtx, cancel := withDefaultTimeout(ctx)
	_, _ = s.exchangeOpack(rcCtx, "TVRCSessionStart", map[string]any{"ProtocolVersionKey": "1.2"})
	cancel()

	// Initial power state snapshot (may be unsupported on newer tvOS).
	stateCtx, cancel := withDefaultTimeout(ctx)
	if resp, err := s.exchangeOpack(stateCtx, "FetchAttentionState", map[string]any{}); err == nil {
		if content, ok := resp["_c"].(map[string]any); ok {
			if state, ok := content["state"].(int64); ok {
				c.updatePowerState(systemStatusToPowerState(state))
			}
		}
	}
	cancel()

	// Live power state updates.
	for _, event := range []string{"SystemStatus", "TVSystemStatus"} {
		if err := s.sendEvent("_interest", map[string]any{"_regEvents": []any{event}}); err != nil {
			return fmt.Errorf("companion: subscribe %s: %w", event, err)
		}
	}
	return nil
}

func (c *Client) handleEvent(name string, content map[string]any) {
	switch name {
	case "SystemStatus", "TVSystemStatus":
		if state, ok := content["state"].(int64); ok {
			c.updatePowerState(systemStatusToPowerState(state))
		}
	}
}

func (c *Client) updatePowerState(state PowerState) {
	if state == PowerStateUnknown {
		return
	}
	c.mu.Lock()
	changed := !c.powerKnown || state != c.powerState
	previous := c.powerState
	c.powerState = state
	c.powerKnown = true
	powerCallbacks := append([]func(PowerState){}, c.powerCallbacks...)
	isOnCallbacks := append([]func(bool){}, c.isOnCallbacks...)
	c.mu.Unlock()

	if !changed {
		return
	}
	for _, cb := range powerCallbacks {
		cb(state)
	}
	if (state == PowerStateOn) != (previous == PowerStateOn) || previous == PowerStateUnknown {
		for _, cb := range isOnCallbacks {
			cb(state == PowerStateOn)
		}
	}
}

func (c *Client) setAvailable(available bool) {
	c.mu.Lock()
	changed := available != c.available
	c.available = available
	callbacks := append([]func(bool){}, c.availableCallbacks...)
	c.mu.Unlock()
	if !changed {
		return
	}
	for _, cb := range callbacks {
		cb(available)
	}
}

func (c *Client) handleConnectionLost(err error) {
	c.setAvailable(false)

	c.mu.Lock()
	reconnecting := c.reconnecting && !c.stopped
	invalidAuth := c.invalidAuth
	c.session = nil
	c.mu.Unlock()

	if !reconnecting {
		return
	}

	go func() {
		delay := time.Second
		for {
			c.mu.Lock()
			stopped := c.stopped
			c.mu.Unlock()
			if stopped {
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			err := c.connectOnce(ctx)
			cancel()
			if err == nil {
				return
			}

			var authErr *InvalidAuth
			if errors.As(err, &authErr) {
				if invalidAuth != nil {
					invalidAuth()
				}
				return
			}

			time.Sleep(delay)
			if delay < 30*time.Second {
				delay *= 2
			}
		}
	}()
}

// KeepReconnecting enables automatic reconnection after connection loss.
// onInvalidAuth is called (once) if the device rejects our credentials, at
// which point re-pairing is required.
func (c *Client) KeepReconnecting(onInvalidAuth func()) {
	c.mu.Lock()
	c.reconnecting = true
	c.invalidAuth = onInvalidAuth
	c.mu.Unlock()
}

// Disconnect stops reconnection and closes the connection.
func (c *Client) Disconnect() {
	c.mu.Lock()
	c.stopped = true
	s := c.session
	sid := c.sid
	c.session = nil
	c.mu.Unlock()

	if s == nil {
		return
	}
	// Best effort: deregister events and stop the session like pyatv does.
	for _, event := range []string{"SystemStatus", "TVSystemStatus"} {
		_ = s.sendEvent("_interest", map[string]any{"_deregEvents": []any{event}})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, _ = s.exchangeOpack(ctx, "_sessionStop", map[string]any{
		"_srvT": "com.apple.tvremoteservices",
		"_sid":  sid,
	})
	cancel()
	s.close(nil)
}

func (c *Client) currentSession() (*session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil {
		return nil, errors.New("companion: not connected")
	}
	return c.session, nil
}

// hidCommand sends a button state change (down = press, up = release).
func (c *Client) hidCommand(ctx context.Context, down bool, command HidCommand) error {
	s, err := c.currentSession()
	if err != nil {
		return err
	}
	buttonState := int64(2)
	if down {
		buttonState = 1
	}
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	_, err = s.exchangeOpack(ctx, "_hidC", map[string]any{
		"_hBtS": buttonState,
		"_hidC": int64(command),
	})
	return err
}

// PressButton sends a full press (down + up) of a remote button.
func (c *Client) PressButton(ctx context.Context, command HidCommand) error {
	if err := c.hidCommand(ctx, true, command); err != nil {
		return err
	}
	return c.hidCommand(ctx, false, command)
}

// Wake turns the Apple TV on (pyatv sends these as a single "up" event).
func (c *Client) Wake(ctx context.Context) error {
	return c.hidCommand(ctx, false, HidWake)
}

// Sleep puts the Apple TV to sleep.
func (c *Client) Sleep(ctx context.Context) error {
	return c.hidCommand(ctx, false, HidSleep)
}

// AppList returns installed launchable apps as bundle id → display name.
func (c *Client) AppList(ctx context.Context) (map[string]string, error) {
	s, err := c.currentSession()
	if err != nil {
		return nil, err
	}
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	resp, err := s.exchangeOpack(ctx, "FetchLaunchableApplicationsEvent", map[string]any{})
	if err != nil {
		return nil, err
	}
	content, ok := resp["_c"].(map[string]any)
	if !ok {
		return nil, errors.New("companion: missing content in app list response")
	}
	apps := make(map[string]string, len(content))
	for bundleID, name := range content {
		if s, ok := name.(string); ok {
			apps[bundleID] = s
		}
	}
	return apps, nil
}

// LaunchApp starts an app by bundle identifier.
func (c *Client) LaunchApp(ctx context.Context, bundleID string) error {
	s, err := c.currentSession()
	if err != nil {
		return err
	}
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()
	_, err = s.exchangeOpack(ctx, "_launchApp", map[string]any{"_bundleID": bundleID})
	return err
}

// StartPairing opens an unauthenticated connection and requests pairing,
// which makes the Apple TV display a PIN.
func (c *Client) StartPairing(ctx context.Context) error {
	pairingID, err := hap.NewPairingID()
	if err != nil {
		return err
	}
	s, err := dialSession(ctx, c.host, c.port)
	if err != nil {
		return err
	}
	pairing := &pairSetup{session: s, name: c.name, pairingID: pairingID}
	if err := pairing.startRequest(ctx); err != nil {
		s.close(nil)
		return err
	}
	c.mu.Lock()
	c.pairing = pairing
	c.mu.Unlock()
	return nil
}

// FinishPairing completes pairing with the PIN shown on the TV and stores
// the credentials in the credentials file.
func (c *Client) FinishPairing(ctx context.Context, pin string) error {
	c.mu.Lock()
	pairing := c.pairing
	c.pairing = nil
	c.mu.Unlock()
	if pairing == nil {
		return errors.New("companion: pairing not started")
	}
	defer pairing.session.close(nil)

	credentials, err := pairing.finish(ctx, pin)
	if err != nil {
		return err
	}
	return hap.SaveCredentials(c.credentialsFile, credentials)
}
