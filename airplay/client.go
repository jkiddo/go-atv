package airplay

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jkiddo/go-atv/hap"
)

// defaultPort is the port AirPlay receivers listen on when discovery is
// skipped.
const defaultPort = 7000

// Client plays media on a single AirPlay receiver. It is not safe for
// concurrent use.
type Client struct {
	name              string
	credentialsPath   string
	address           string
	port              int
	properties        map[string]string
	authMode          string
	fairPlayControl   bool
	deviceID          string
	mediaURLHandler   func(string)
	playbackHandler   func(map[string]any)
	diagnosticHandler func(DiagnosticEvent)

	// pairing state between StartPairing and FinishPairing
	pairingConn *connection
	pairing     pairingProcedure

	// password pairing state between StartPasswordPairing and
	// FinishPasswordPairing. Legacy Apple TVs use this separate HTTP Digest
	// password in addition to pair-setup credentials.
	passwordConn *connection
}

type pairingProcedure interface {
	startRequest(context.Context) error
	finish(context.Context, string) (hap.Credentials, error)
}

// Option configures a Client.
type Option func(*Client)

// WithPort sets the AirPlay port (from discovery); default is 7000.
func WithPort(port int) Option {
	return func(c *Client) {
		if port > 0 {
			c.port = port
		}
	}
}

// WithProperties supplies the mDNS TXT properties from discovery, used to
// pick protocol version and pairing mode without extra round trips.
func WithProperties(properties map[string]string) Option {
	return func(c *Client) { c.properties = properties }
}

// WithPlaybackInfoHandler observes playback-info updates received on the
// owning AirPlay control connection. The handler is called synchronously and
// must return quickly.
func WithPlaybackInfoHandler(handler func(map[string]any)) Option {
	return func(c *Client) { c.playbackHandler = handler }
}

// WithMediaURLHandler observes the exact URL submitted by PlayURL, including
// temporary URLs for local files. The synchronous callback runs after URL
// resolution and before sending; it does not indicate successful playback.
func WithMediaURLHandler(handler func(string)) Option {
	return func(c *Client) { c.mediaURLHandler = handler }
}

// WithAuthMode overrides how the client authenticates against the receiver.
// "auto" (default) follows advertised features and stored credentials;
// "open" declares a receiver that runs without AirPlay security, forcing the
// unauthenticated v1 flow for play and status requests.
func WithAuthMode(mode string) Option {
	return func(c *Client) { c.authMode = mode }
}

// New creates a client for the receiver at address. name is shown on the
// Apple TV during pairing; credentialsPath stores the AirPlay credentials
// (pyatv-compatible format).
func New(name, credentialsPath, address string, opts ...Option) *Client {
	c := &Client{
		name:            name,
		credentialsPath: credentialsPath,
		address:         address,
		port:            defaultPort,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) openAuth() bool {
	return c.authMode == "open"
}

// openDeviceID returns the X-Apple-Device-ID used for credential-less
// sessions. Receivers use it only for playback bookkeeping.
func (c *Client) openDeviceID() string {
	if c.deviceID == "" {
		id := make([]byte, 6)
		if _, err := rand.Read(id); err != nil {
			return "0x0"
		}
		c.deviceID = fmt.Sprintf("0x%x", id)
	}
	return c.deviceID
}

// StartPairing begins the pairing protocol appropriate for the receiver; a
// PIN appears on the Apple TV.
func (c *Client) StartPairing(ctx context.Context) error {
	conn, err := dial(ctx, c.address, c.port)
	if err != nil {
		return err
	}
	features, err := c.features(ctx, newRTSPSession(conn))
	if err != nil {
		conn.close()
		return err
	}

	var pairing pairingProcedure
	if features != 0 && !features.isVersion2() {
		credentials, err := newLegacyCredentials()
		if err != nil {
			conn.close()
			return err
		}
		pairing = &legacyPairSetup{conn: conn, credentials: credentials}
	} else {
		pairingID, err := hap.NewPairingID()
		if err != nil {
			conn.close()
			return err
		}
		pairing = &pairSetup{conn: conn, name: c.name, pairingID: pairingID}
	}
	if err := pairing.startRequest(ctx); err != nil {
		conn.close()
		return err
	}
	c.pairingConn = conn
	c.pairing = pairing
	return nil
}

// FinishPairing completes pair-setup with the PIN shown on the TV and saves
// the credentials.
func (c *Client) FinishPairing(ctx context.Context, pin string) error {
	if c.pairing == nil {
		return errors.New("airplay: pairing not started")
	}
	defer func() {
		c.pairingConn.close()
		c.pairingConn = nil
		c.pairing = nil
	}()

	credentials, err := c.pairing.finish(ctx, pin)
	if err != nil {
		return err
	}
	return hap.SaveCredentials(c.credentialsPath, credentials)
}

// StartPasswordPairing checks whether a legacy receiver also requires an
// on-screen AirPlay code. It returns true after causing that code to appear on
// the TV; the caller must then pass it to FinishPasswordPairing.
func (c *Client) StartPasswordPairing(ctx context.Context) (bool, error) {
	credentials, err := c.loadCredentials()
	if err != nil {
		return false, err
	}
	if credentials == nil {
		return false, errNotPaired
	}

	conn, err := dial(ctx, c.address, c.port)
	if err != nil {
		return false, err
	}
	features, err := c.features(ctx, newRTSPSession(conn, credentials))
	if err != nil {
		conn.close()
		return false, err
	}
	legacy := (features != 0 && !features.isVersion2()) || (features == 0 && credentials.IsLegacy())
	if !legacy {
		conn.close()
		return false, nil
	}
	if err := legacyCredentialTypeError(features, credentials); err != nil {
		conn.close()
		return false, err
	}
	if err := c.verifyLegacyWithDiagnostics(ctx, conn, *credentials); err != nil {
		conn.close()
		return false, err
	}

	response, err := conn.get(ctx, "/playback-info", nil)
	if err == nil {
		c.emitDiagnostic(DiagnosticEvent{Stage: "code-challenge", Result: "response", StatusCode: response.Code, Challenge: response.Headers["www-authenticate"] != ""})
	} else {
		c.emitDiagnostic(DiagnosticEvent{Stage: "code-challenge", Result: "transport-error"})
	}
	if err != nil {
		conn.close()
		return false, err
	}
	if response.Code != http.StatusUnauthorized {
		conn.close()
		if err := errStatus(response, "GET /playback-info"); err != nil {
			return false, err
		}
		return false, nil
	}
	digest, err := parseDigestChallenge(response.Headers["www-authenticate"], "AirPlay", "")
	if err != nil {
		conn.close()
		return false, err
	}
	conn.digest = digest
	c.passwordConn = conn
	return true, nil
}

// FinishPasswordPairing validates and persists the separate AirPlay code
// displayed by a legacy receiver.
func (c *Client) FinishPasswordPairing(ctx context.Context, password string) error {
	if c.passwordConn == nil || c.passwordConn.digest == nil {
		return errors.New("airplay: password pairing not started")
	}
	conn := c.passwordConn
	conn.digest.password = strings.TrimSpace(password)
	response, err := conn.get(ctx, "/playback-info", nil)
	if err == nil {
		c.emitDiagnostic(DiagnosticEvent{Stage: "code-submit", Result: "response", StatusCode: response.Code, Challenge: response.Headers["www-authenticate"] != ""})
	} else {
		c.emitDiagnostic(DiagnosticEvent{Stage: "code-submit", Result: "transport-error"})
	}
	if err != nil {
		conn.close()
		c.passwordConn = nil
		return err
	}
	if response.Code == http.StatusUnauthorized || response.Code == http.StatusForbidden || response.Code == 470 {
		if challenge := response.Headers["www-authenticate"]; challenge != "" {
			if digest, parseErr := parseDigestChallenge(challenge, "AirPlay", ""); parseErr == nil {
				conn.digest = digest
			}
		} else {
			conn.digest.password = ""
		}
		return &InvalidAuth{Message: "incorrect AirPlay code"}
	}
	if err := errStatus(response, "GET /playback-info"); err != nil {
		conn.close()
		c.passwordConn = nil
		return err
	}
	if err := c.saveLegacyPassword(conn.digest.password); err != nil {
		conn.close()
		c.passwordConn = nil
		return err
	}
	conn.close()
	c.passwordConn = nil
	return nil
}

// CancelPairing releases any in-progress pair-setup or password challenge.
func (c *Client) CancelPairing() {
	if c.pairingConn != nil {
		c.pairingConn.close()
	}
	if c.passwordConn != nil {
		c.passwordConn.close()
	}
	c.pairingConn = nil
	c.pairing = nil
	c.passwordConn = nil
}

// PlayURL plays media from a URL (or a local file path, which is served to
// the device over a temporary HTTP server) and blocks until playback ends
// or ctx is cancelled. position is the start position in seconds.
func (c *Client) PlayURL(ctx context.Context, mediaURL string, position float64) error {
	if _, err := os.Stat(mediaURL); err == nil {
		served, stop, err := serveLocalFile(c.address, c.port, mediaURL)
		if err != nil {
			return err
		}
		defer stop()
		mediaURL = served
	}

	if c.mediaURLHandler != nil {
		c.mediaURLHandler(mediaURL)
	}
	conn, err := dial(ctx, c.address, c.port)
	if err != nil {
		return err
	}
	defer conn.close()

	credentials, err := c.loadCredentials()
	if err != nil {
		return err
	}
	rtsp := newRTSPSession(conn, credentials)
	rtsp.playbackHandler = c.playbackHandler
	features, err := c.features(ctx, rtsp)
	if err != nil {
		return err
	}
	if features != 0 && !features.SupportsPlayURL() {
		return errors.New("airplay: receiver does not announce AirPlay video support")
	}

	// Unknown features (no discovery data and no /info) are treated as
	// AirPlay 2, which covers all recent hardware.
	legacy := features != 0 && !features.isVersion2()
	if c.fairPlayControl {
		if !legacy {
			return errors.New("airplay: fp-setup2 is enabled only for legacy video receivers")
		}
		return c.playURLFairPlay(ctx, rtsp, credentials, mediaURL, position)
	}
	if c.openAuth() || (legacy && credentials == nil) {
		// Open receiver (declared as having no security, or a v1 receiver
		// without stored credentials): stream the unauthenticated v1 flow.
		// A protected receiver answers /play with 401, which surfaces as
		// invalid authentication instead of streaming over a guest session.
		// playURLV1 owns cancellation so it can stop the interrupt handler
		// before sending /stop on this connection during cleanup.
		return playURLV1(ctx, rtsp, mediaURL, position, c.legacySessionPath(), c.openDeviceID())
	}
	if !legacy {
		if credentials == nil && features != 0 && !features.supportsTransient() {
			return errNotPaired
		}
		if credentials != nil {
			if err := legacyCredentialTypeError(features, credentials); err != nil {
				return err
			}
		}
		verifier, err := verifyConnection(ctx, conn, credentials)
		if err != nil {
			return err
		}
		stopInterrupt := interruptOnCancel(ctx, conn)
		defer stopInterrupt()
		return playURLV2(ctx, rtsp, verifier, mediaURL, position)
	}
	if err := legacyCredentialTypeError(features, credentials); err != nil {
		return err
	}
	if err := c.verifyLegacyWithDiagnostics(ctx, conn, *credentials); err != nil {
		return err
	}
	password, err := c.loadLegacyPassword()
	if err != nil {
		return err
	}
	// Some legacy receivers reject an unauthenticated /play with 453 rather
	// than a Digest challenge. Obtain a challenge on this same connection
	// first, while still allowing /play to refresh a changed nonce.
	conn.diagnosticHandler = c.emitDiagnostic
	if err := primeLegacyDigestWithDiagnostics(ctx, conn, password, c.emitDiagnostic); err != nil {
		var status *StatusError
		if !errors.As(err, &status) || status.Code != 453 {
			return err
		}
		// A refused status probe is not evidence of idle playback or bad
		// credentials. Let the explicit play request report its own result.
	}
	return playURLV1(ctx, rtsp, mediaURL, position, c.legacySessionPath(), legacyDeviceID(*credentials))
}

func (c *Client) legacySessionPath() string {
	if c.credentialsPath == "" {
		return ""
	}
	return c.credentialsPath + ".session"
}

func (c *Client) legacyPasswordPath() string {
	if c.credentialsPath == "" {
		return ""
	}
	return c.credentialsPath + ".password"
}

// PlaybackInfo returns the receiver's current AirPlay playback state. When
// credentials are available it performs pair-verify before requesting the
// state, which is required by receivers with AirPlay access control enabled.
func (c *Client) PlaybackInfo(ctx context.Context) (map[string]any, error) {
	conn, err := dial(ctx, c.address, c.port)
	if err != nil {
		return nil, err
	}
	defer conn.close()

	credentials, err := c.loadCredentials()
	if err != nil {
		return nil, err
	}
	rtsp := newRTSPSession(conn, credentials)
	features, err := c.features(ctx, rtsp)
	if err != nil {
		return nil, err
	}
	legacy := features != 0 && !features.isVersion2()
	var statusHeaders []header
	if c.openAuth() || (legacy && credentials == nil) {
		// Open receiver: probe unauthenticated. A protected receiver answers
		// the status request with 401, reported as invalid authentication.
		conn.diagnosticHandler = c.emitDiagnostic
		if sessionID := loadLegacySessionID(c.legacySessionPath()); sessionID != "" {
			statusHeaders = []header{{"X-Apple-Session-ID", sessionID}}
		}
	} else if !legacy {
		if credentials == nil && features != 0 && !features.supportsTransient() {
			return nil, errNotPaired
		}
		if credentials != nil {
			if err := legacyCredentialTypeError(features, credentials); err != nil {
				return nil, err
			}
		}
		if _, err := verifyConnection(ctx, conn, credentials); err != nil {
			return nil, err
		}
	} else {
		if err := legacyCredentialTypeError(features, credentials); err != nil {
			return nil, err
		}
		if err := c.verifyLegacyWithDiagnostics(ctx, conn, *credentials); err != nil {
			return nil, err
		}
		password, err := c.loadLegacyPassword()
		if err != nil {
			return nil, err
		}
		// Correlate reconnect status requests with the last playback session,
		// including the unauthenticated request used to obtain a challenge.
		if sessionID := loadLegacySessionID(c.legacySessionPath()); sessionID != "" {
			statusHeaders = []header{{"X-Apple-Session-ID", sessionID}}
		}
		if err := primeLegacyDigestWithDiagnostics(ctx, conn, password, c.emitDiagnostic, statusHeaders...); err != nil {
			return nil, err
		}
	}

	response, err := conn.exchangeWithDigestRetry(ctx, request{Method: "GET", URI: "/playback-info", Headers: statusHeaders})
	if err == nil {
		c.emitDiagnostic(DiagnosticEvent{Stage: "playback-info", Result: "response", StatusCode: response.Code, Challenge: response.Headers["www-authenticate"] != ""})
	} else {
		c.emitDiagnostic(DiagnosticEvent{Stage: "playback-info", Result: "transport-error"})
	}
	if err != nil {
		// Legacy Apple TVs close a standalone authenticated status connection
		// when no playback session exists. pyatv likewise treats a lost
		// playback-info connection as playback having stopped.
		if legacy && errors.Is(err, io.EOF) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	if response.Code == http.StatusUnauthorized || response.Code == http.StatusForbidden || response.Code == 470 {
		return nil, &InvalidAuth{Message: fmt.Sprintf("device rejected playback-info (status %d); pairing may be required", response.Code)}
	}
	if err := errStatus(response, "GET /playback-info"); err != nil {
		return nil, err
	}
	return unpackPlist(response.Body)
}

// loadCredentials returns stored credentials or nil when not paired yet.
func (c *Client) loadCredentials() (*hap.Credentials, error) {
	credentials, err := hap.LoadCredentials(c.credentialsPath)
	c.traceCredentials(credentials, err)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return &credentials, nil
}

func (c *Client) loadLegacyPassword() (string, error) {
	raw, err := os.ReadFile(c.legacyPasswordPath())
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func (c *Client) saveLegacyPassword(password string) error {
	path := c.legacyPasswordPath()
	if path == "" {
		return errors.New("airplay: credentials path is required to save the AirPlay code")
	}
	if err := os.WriteFile(path, []byte(password+"\n"), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func primeLegacyDigest(ctx context.Context, conn *connection, password string) error {
	return primeLegacyDigestWithDiagnostics(ctx, conn, password, func(DiagnosticEvent) {})
}

func primeLegacyDigestWithDiagnostics(ctx context.Context, conn *connection, password string, emit func(DiagnosticEvent), headers ...header) error {
	emit(DiagnosticEvent{Stage: "saved-airplay-code", Result: "checked", SavedCode: password != ""})
	conn.legacyPassword = password
	response, err := conn.get(ctx, "/playback-info", headers)
	if err != nil {
		emit(DiagnosticEvent{Stage: "digest-probe", Result: "transport-error"})
		return err
	}
	emit(DiagnosticEvent{Stage: "digest-probe", Result: "response", StatusCode: response.Code, Challenge: response.Headers["www-authenticate"] != ""})
	if response.Code != http.StatusUnauthorized {
		return errStatus(response, "GET /playback-info")
	}
	if password == "" {
		return &InvalidAuth{Message: "receiver requires an on-screen AirPlay code"}
	}
	digest, err := parseDigestChallenge(response.Headers["www-authenticate"], "AirPlay", password)
	if err != nil {
		return err
	}
	conn.digest = digest
	return nil
}

func legacyDeviceID(credentials hap.Credentials) string {
	return fmt.Sprintf("0x%x", credentials.ClientID[:6])
}

// features returns the receiver's feature flags, from discovery properties
// when available, otherwise from GET /info. Zero means unknown.
func (c *Client) features(ctx context.Context, rtsp *rtspSession) (Features, error) {
	if features := deviceFeatures(c.properties); features != 0 {
		return features, nil
	}

	infoCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := rtsp.exchange(infoCtx, "GET", "/info", nil, nil)
	if err != nil || resp.Code != 200 {
		return 0, nil // /info not supported; assume defaults
	}
	parsed, err := unpackPlist(resp.Body)
	if err != nil {
		return 0, nil
	}
	if features, ok := plistInt(parsed["features"]); ok {
		return Features(uint64(features)), nil
	}
	return 0, nil
}

// serveLocalFile exposes a single local file over HTTP on the interface
// that reaches the receiver, returning the URL to play and a stop function.
func serveLocalFile(deviceAddress string, devicePort int, path string) (string, func(), error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}

	localIP, err := localAddressReaching(deviceAddress, devicePort)
	if err != nil {
		return "", nil, err
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(localIP, "0"))
	if err != nil {
		return "", nil, err
	}

	fileName := filepath.Base(absPath)
	mux := http.NewServeMux()
	mux.HandleFunc("/"+url.PathEscape(fileName), func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, absPath)
	})
	server := &http.Server{Handler: mux}
	go server.Serve(listener)

	fileURL := fmt.Sprintf("http://%s/%s", listener.Addr().String(), url.PathEscape(fileName))
	return fileURL, func() { server.Close() }, nil
}

// localAddressReaching returns the local IP used to reach the device.
func localAddressReaching(address string, port int) (string, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(address, fmt.Sprintf("%d", port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	return host, err
}
