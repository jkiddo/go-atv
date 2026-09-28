package companion

// End-to-end test against a minimal in-process fake Apple TV implementing
// the server side of HAP pair-setup/pair-verify and a few Companion
// commands. Exercises pairing, encryption, commands and pushed events.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"math/big"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/jkiddo/go-atv/hap"
	"github.com/jkiddo/go-atv/opack"
	"github.com/jkiddo/go-atv/tlv8"
)

const (
	fakePIN   = "1111"
	fakeATVID = "fake-atv-identifier"
)

// --- SRP server side (mirrors srptools' formulas) ---

var srpPrime, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
		"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"+
		"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"+
		"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"+
		"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"+
		"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"+
		"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16)

func minBytes(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) == 0 {
		return []byte{0}
	}
	return b
}

func padToPrime(v *big.Int) []byte {
	width := len(minBytes(srpPrime))
	b := minBytes(v)
	padded := make([]byte, width)
	copy(padded[width-len(b):], b)
	return padded
}

func hashInt(args ...[]byte) *big.Int {
	h := sha512.New()
	for _, a := range args {
		h.Write(a)
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

type srpServer struct {
	salt    []byte
	b       *big.Int
	B       *big.Int
	v       *big.Int
	K       []byte
	proofM1 []byte
	proofM2 []byte
}

func newSRPServer(pin string) *srpServer {
	g := big.NewInt(5)
	salt := make([]byte, 16)
	rand.Read(salt)
	inner := sha512.Sum512([]byte("Pair-Setup:" + pin))
	x := hashInt(salt, inner[:])
	v := new(big.Int).Exp(g, x, srpPrime)
	k := hashInt(minBytes(srpPrime), padToPrime(g))

	bBytes := make([]byte, 32)
	rand.Read(bBytes)
	b := new(big.Int).SetBytes(bBytes)
	B := new(big.Int).Add(new(big.Int).Mul(k, v), new(big.Int).Exp(g, b, srpPrime))
	B.Mod(B, srpPrime)
	return &srpServer{salt: salt, b: b, B: B, v: v}
}

// processClient computes the session key from A and checks the client proof.
func (s *srpServer) processClient(aBytes, clientProof []byte) bool {
	A := new(big.Int).SetBytes(aBytes)
	u := hashInt(padToPrime(A), padToPrime(s.B))
	S := new(big.Int).Exp(
		new(big.Int).Mul(A, new(big.Int).Exp(s.v, u, srpPrime)),
		s.b, srpPrime)
	K := sha512.Sum512(minBytes(S))
	s.K = K[:]

	g := big.NewInt(5)
	hN := hashInt(minBytes(srpPrime))
	hG := hashInt(minBytes(g))
	hI := hashInt([]byte("Pair-Setup"))
	m1 := sha512.New()
	m1.Write(minBytes(new(big.Int).Xor(hN, hG)))
	m1.Write(minBytes(hI))
	m1.Write(s.salt)
	m1.Write(minBytes(A))
	m1.Write(minBytes(s.B))
	m1.Write(s.K)
	s.proofM1 = m1.Sum(nil)

	m2 := sha512.New()
	m2.Write(minBytes(A))
	m2.Write(s.proofM1)
	m2.Write(s.K)
	s.proofM2 = m2.Sum(nil)

	return string(clientProof) == string(s.proofM1)
}

// --- fake Apple TV ---

type fakeATV struct {
	t        *testing.T
	listener net.Listener

	signingKey ed25519.PrivateKey

	mu           sync.Mutex
	clientLTPK   []byte
	clientID     []byte
	hidCommands  []int64
	systemStatus int64
	eventConn    net.Conn
	eventCipher  *hap.Cipher
}

func newFakeATV(t *testing.T) *fakeATV {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	atv := &fakeATV{t: t, listener: listener, signingKey: signingKey, systemStatus: 3 /* awake */}
	go atv.acceptLoop()
	t.Cleanup(func() { listener.Close() })
	return atv
}

func (a *fakeATV) port() int {
	return a.listener.Addr().(*net.TCPAddr).Port
}

func (a *fakeATV) acceptLoop() {
	for {
		conn, err := a.listener.Accept()
		if err != nil {
			return
		}
		go a.handleConn(conn)
	}
}

func (a *fakeATV) sendFrame(conn net.Conn, cipher *hap.Cipher, frameType FrameType, payload []byte) {
	length := len(payload)
	if cipher != nil && length > 0 {
		length += 16
	}
	header := frameHeader(frameType, length)
	if cipher != nil && len(payload) > 0 {
		payload = cipher.Encrypt(payload, nil, header)
	}
	conn.Write(append(header, payload...))
}

func (a *fakeATV) sendAuth(conn net.Conn, frameType FrameType, tlvData []byte) {
	payload, err := opack.Pack(map[string]any{"_pd": tlvData})
	if err != nil {
		a.t.Error(err)
		return
	}
	a.sendFrame(conn, nil, frameType, payload)
}

func (a *fakeATV) handleConn(conn net.Conn) {
	defer conn.Close()

	var srp *srpServer
	var setupCipher *hap.Cipher
	var verifyShared []byte
	var sessionCipher *hap.Cipher

	for {
		frameType, payload, header, err := readFrame(conn)
		if err != nil {
			return
		}
		if sessionCipher != nil && len(payload) > 0 {
			payload, err = sessionCipher.Decrypt(payload, nil, header)
			if err != nil {
				a.t.Error("server decrypt:", err)
				return
			}
		}
		value, _, err := opack.Unpack(payload)
		if err != nil {
			a.t.Error("server unpack:", err)
			return
		}
		message, _ := value.(map[string]any)

		switch frameType {
		case FramePSStart:
			srp = newSRPServer(fakePIN)
			a.sendAuth(conn, FramePSNext, tlv8.Write(
				tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x02}},
				tlv8.Item{Tag: tlv8.TagSalt, Value: srp.salt},
				tlv8.Item{Tag: tlv8.TagPublicKey, Value: minBytes(srp.B)},
			))

		case FramePSNext:
			raw, _ := message["_pd"].([]byte)
			tlv, err := tlv8.Read(raw)
			if err != nil {
				a.t.Error(err)
				return
			}
			switch tlv[tlv8.TagSeqNo][0] {
			case 0x03: // client public key + proof
				if !srp.processClient(tlv[tlv8.TagPublicKey], tlv[tlv8.TagProof]) {
					a.sendAuth(conn, FramePSNext, tlv8.Write(
						tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x04}},
						tlv8.Item{Tag: tlv8.TagError, Value: []byte{tlv8.ErrorAuthentication}},
					))
					return
				}
				a.sendAuth(conn, FramePSNext, tlv8.Write(
					tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x04}},
					tlv8.Item{Tag: tlv8.TagProof, Value: srp.proofM2},
				))
			case 0x05: // encrypted client identity
				sessionKey := hap.HKDFExpand("Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info", srp.K)
				setupCipher, err = hap.NewCipher(sessionKey, sessionKey, 8)
				if err != nil {
					a.t.Error(err)
					return
				}
				decrypted, err := setupCipher.Decrypt(tlv[tlv8.TagEncryptedData], []byte("PS-Msg05"), nil)
				if err != nil {
					a.t.Error("M5 decrypt:", err)
					return
				}
				clientTLV, err := tlv8.Read(decrypted)
				if err != nil {
					a.t.Error(err)
					return
				}
				a.mu.Lock()
				a.clientLTPK = clientTLV[tlv8.TagPublicKey]
				a.clientID = clientTLV[tlv8.TagIdentifier]
				a.mu.Unlock()

				accessoryX := hap.HKDFExpand("Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info", srp.K)
				var info []byte
				info = append(info, accessoryX...)
				info = append(info, []byte(fakeATVID)...)
				info = append(info, a.signingKey.Public().(ed25519.PublicKey)...)
				signature := ed25519.Sign(a.signingKey, info)
				inner := tlv8.Write(
					tlv8.Item{Tag: tlv8.TagIdentifier, Value: []byte(fakeATVID)},
					tlv8.Item{Tag: tlv8.TagPublicKey, Value: a.signingKey.Public().(ed25519.PublicKey)},
					tlv8.Item{Tag: tlv8.TagSignature, Value: signature},
				)
				encrypted := setupCipher.Encrypt(inner, []byte("PS-Msg06"), nil)
				a.sendAuth(conn, FramePSNext, tlv8.Write(
					tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x06}},
					tlv8.Item{Tag: tlv8.TagEncryptedData, Value: encrypted},
				))
			}

		case FramePVStart:
			raw, _ := message["_pd"].([]byte)
			tlv, _ := tlv8.Read(raw)
			clientPublic := tlv[tlv8.TagPublicKey]

			var private [32]byte
			rand.Read(private[:])
			public, _ := curve25519.X25519(private[:], curve25519.Basepoint)
			verifyShared, _ = curve25519.X25519(private[:], clientPublic)

			sessionKey := hap.HKDFExpand("Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", verifyShared)
			cipher, _ := hap.NewCipher(sessionKey, sessionKey, 8)

			var info []byte
			info = append(info, public...)
			info = append(info, []byte(fakeATVID)...)
			info = append(info, clientPublic...)
			signature := ed25519.Sign(a.signingKey, info)
			inner := tlv8.Write(
				tlv8.Item{Tag: tlv8.TagIdentifier, Value: []byte(fakeATVID)},
				tlv8.Item{Tag: tlv8.TagSignature, Value: signature},
			)
			encrypted := cipher.Encrypt(inner, []byte("PV-Msg02"), nil)
			a.sendAuth(conn, FramePVNext, tlv8.Write(
				tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x02}},
				tlv8.Item{Tag: tlv8.TagPublicKey, Value: public},
				tlv8.Item{Tag: tlv8.TagEncryptedData, Value: encrypted},
			))

		case FramePVNext:
			a.sendAuth(conn, FramePVNext, tlv8.Write(
				tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x04}},
			))
			// Encryption starts after our M4 response. Server output key is
			// the client's input key and vice versa.
			outputKey := hap.HKDFExpand("", "ServerEncrypt-main", verifyShared)
			inputKey := hap.HKDFExpand("", "ClientEncrypt-main", verifyShared)
			cipher, err := hap.NewCipher(outputKey, inputKey, 12)
			if err != nil {
				a.t.Error(err)
				return
			}
			sessionCipher = cipher
			a.mu.Lock()
			a.eventConn = conn
			a.eventCipher = cipher
			a.mu.Unlock()

		case FrameEOpack:
			a.handleOpack(conn, sessionCipher, message)
		}
	}
}

func (a *fakeATV) respond(conn net.Conn, cipher *hap.Cipher, request map[string]any, content map[string]any) {
	response := map[string]any{
		"_i": request["_i"],
		"_t": int64(3),
		"_x": request["_x"],
		"_c": content,
	}
	payload, err := opack.Pack(response)
	if err != nil {
		a.t.Error(err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sendFrame(conn, cipher, FrameEOpack, payload)
}

func (a *fakeATV) handleOpack(conn net.Conn, cipher *hap.Cipher, message map[string]any) {
	messageType, _ := message["_t"].(int64)
	if messageType == int64(messageTypeEvent) {
		return // _interest registrations etc.
	}
	identifier, _ := message["_i"].(string)
	switch identifier {
	case "_systemInfo", "_launchApp", "TVRCSessionStart":
		a.respond(conn, cipher, message, map[string]any{})
	case "_sessionStart":
		a.respond(conn, cipher, message, map[string]any{"_sid": int64(0xBEEF)})
	case "_sessionStop":
		a.respond(conn, cipher, message, map[string]any{})
	case "FetchAttentionState":
		a.mu.Lock()
		state := a.systemStatus
		a.mu.Unlock()
		a.respond(conn, cipher, message, map[string]any{"state": state})
	case "FetchLaunchableApplicationsEvent":
		a.respond(conn, cipher, message, map[string]any{
			"com.apple.TVSettings": "Settings",
			"com.netflix.Netflix":  "Netflix",
		})
	case "_hidC":
		content, _ := message["_c"].(map[string]any)
		command, _ := content["_hidC"].(int64)
		buttonState, _ := content["_hBtS"].(int64)
		a.mu.Lock()
		a.hidCommands = append(a.hidCommands, command<<8|buttonState)
		a.mu.Unlock()
		a.respond(conn, cipher, message, map[string]any{})
	default:
		a.respond(conn, cipher, message, map[string]any{})
	}
}

// pushSystemStatus sends a TVSystemStatus event on the active connection.
func (a *fakeATV) pushSystemStatus(state int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.eventConn == nil {
		a.t.Error("no active event connection")
		return
	}
	a.systemStatus = state
	payload, err := opack.Pack(map[string]any{
		"_i": "TVSystemStatus",
		"_t": int64(1),
		"_x": int64(99),
		"_c": map[string]any{"state": state},
	})
	if err != nil {
		a.t.Error(err)
		return
	}
	a.sendFrame(a.eventConn, a.eventCipher, FrameEOpack, payload)
}

// --- the test ---

func TestPairConnectAndControl(t *testing.T) {
	atv := newFakeATV(t)
	credentialsFile := filepath.Join(t.TempDir(), "credentials")
	client := New("goatv-test", credentialsFile, "127.0.0.1", WithPort(atv.port()))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Pair.
	if client.HasCredentials() {
		t.Fatal("should not have credentials yet")
	}
	if err := client.StartPairing(ctx); err != nil {
		t.Fatal("start pairing:", err)
	}
	if err := client.FinishPairing(ctx, fakePIN); err != nil {
		t.Fatal("finish pairing:", err)
	}
	if !client.HasCredentials() {
		t.Fatal("credentials not saved")
	}

	// Wrong PIN must fail.
	badClient := New("goatv-test", filepath.Join(t.TempDir(), "credentials"), "127.0.0.1", WithPort(atv.port()))
	if err := badClient.StartPairing(ctx); err != nil {
		t.Fatal(err)
	}
	if err := badClient.FinishPairing(ctx, "9999"); err == nil {
		t.Fatal("pairing with wrong PIN should fail")
	}

	// Connect and observe state.
	powerStates := make(chan PowerState, 8)
	client.AddPowerStateUpdatedCallback(func(state PowerState) { powerStates <- state })

	if err := client.Connect(ctx); err != nil {
		t.Fatal("connect:", err)
	}
	defer client.Disconnect()

	select {
	case state := <-powerStates:
		if state != PowerStateOn {
			t.Fatalf("initial power state = %v, want on", state)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no initial power state")
	}

	// Pushed event: device goes to sleep.
	atv.pushSystemStatus(1)
	select {
	case state := <-powerStates:
		if state != PowerStateOff {
			t.Fatalf("pushed power state = %v, want off", state)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no pushed power state update")
	}
	if on, known := client.IsOn(); !known || on {
		t.Errorf("IsOn = %v/%v, want false/true", on, known)
	}

	// Button press: down then up.
	if err := client.PressButton(ctx, HidSelect); err != nil {
		t.Fatal("press button:", err)
	}
	// Wake: single "up" event, like pyatv.
	if err := client.Wake(ctx); err != nil {
		t.Fatal("wake:", err)
	}
	atv.mu.Lock()
	hid := append([]int64{}, atv.hidCommands...)
	atv.mu.Unlock()
	want := []int64{int64(HidSelect)<<8 | 1, int64(HidSelect)<<8 | 2, int64(HidWake)<<8 | 2}
	if len(hid) != len(want) {
		t.Fatalf("hid commands = %v, want %v", hid, want)
	}
	for i := range want {
		if hid[i] != want[i] {
			t.Fatalf("hid commands = %v, want %v", hid, want)
		}
	}

	// App list.
	apps, err := client.AppList(ctx)
	if err != nil {
		t.Fatal("app list:", err)
	}
	if apps["com.netflix.Netflix"] != "Netflix" || len(apps) != 2 {
		t.Errorf("apps = %v", apps)
	}

	// Launch app.
	if err := client.LaunchApp(ctx, "com.netflix.Netflix"); err != nil {
		t.Fatal("launch app:", err)
	}
}
