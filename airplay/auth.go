package airplay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"

	"github.com/jkiddo/go-atv/hap"
	"github.com/jkiddo/go-atv/opack"
	"github.com/jkiddo/go-atv/tlv8"
)

// AirPlay auth endpoints use an older user agent and the X-Apple-HKP header
// selecting the HomeKit pairing variant (3 = HAP, 4 = transient), mirroring
// pyatv's _AIRPLAY_HEADERS.
const authUserAgent = "AirPlay/320.20"

func authHeaders(hkp string) []header {
	return []header{
		{"Connection", "keep-alive"},
		{"X-Apple-HKP", hkp},
	}
}

// Encryption key derivation parameters for the control connection and the
// event channel (pyatv auth/__init__.py and airplayv2.py).
const (
	controlSalt       = "Control-Salt"
	controlOutputInfo = "Control-Write-Encryption-Key"
	controlInputInfo  = "Control-Read-Encryption-Key"

	eventsSalt      = "Events-Salt"
	eventsWriteInfo = "Events-Write-Encryption-Key"
	eventsReadInfo  = "Events-Read-Encryption-Key"

	transientPIN = "3939"
)

// InvalidAuth indicates the Apple TV rejected our credentials or PIN.
type InvalidAuth struct{ Message string }

func (e *InvalidAuth) Error() string { return "airplay: " + e.Message }

// verifier holds the shared secret established by pair-verify (or transient
// pair-setup) and derives per-channel encryption keys from it.
type verifier struct {
	shared []byte
}

// encryptionKeys derives the (output, input) keys for a channel, mirroring
// pyatv's SRPAuthHandler.verify2.
func (v *verifier) encryptionKeys(salt, outputInfo, inputInfo string) (outputKey, inputKey []byte) {
	return hap.HKDFExpand(salt, outputInfo, v.shared), hap.HKDFExpand(salt, inputInfo, v.shared)
}

// authPost sends TLV8 pairing data to an auth endpoint and parses the TLV8
// response, surfacing HAP error codes.
func authPost(ctx context.Context, c *connection, uri, hkp string, items ...tlv8.Item) (map[byte][]byte, error) {
	resp, err := c.exchange(ctx, request{
		Method:      "POST",
		URI:         uri,
		UserAgent:   authUserAgent,
		ContentType: "application/octet-stream",
		Headers:     authHeaders(hkp),
		Body:        tlv8.Write(items...),
	})
	if err != nil {
		return nil, err
	}
	if err := errStatus(resp, "POST "+uri); err != nil {
		return nil, err
	}
	tlv, err := tlv8.Read(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("airplay: %s response: %w", uri, err)
	}
	if errValue, ok := tlv[tlv8.TagError]; ok && len(errValue) > 0 {
		if errValue[0] == tlv8.ErrorAuthentication {
			return nil, &InvalidAuth{Message: "device rejected authentication"}
		}
		return nil, fmt.Errorf("airplay: %s error code %d", uri, errValue[0])
	}
	return tlv, nil
}

// pairPinStart asks the Apple TV to display a pairing PIN (no-op body).
func pairPinStart(ctx context.Context, c *connection, hkp string) error {
	resp, err := c.exchange(ctx, request{
		Method:    "POST",
		URI:       "/pair-pin-start",
		UserAgent: authUserAgent,
		Headers:   authHeaders(hkp),
	})
	if err != nil {
		return err
	}
	return errStatus(resp, "POST /pair-pin-start")
}

// pairSetup implements HAP pair-setup (M1..M6) over the AirPlay HTTP
// endpoints, mirroring pyatv's AirPlayHapPairSetupProcedure. The PIN is
// displayed on the Apple TV after startRequest.
type pairSetup struct {
	conn *connection
	name string

	pairingID    []byte
	atvSalt      []byte
	atvPublicKey []byte
}

// startRequest sends M1, which makes the Apple TV display a PIN.
func (p *pairSetup) startRequest(ctx context.Context) error {
	if err := pairPinStart(ctx, p.conn, "3"); err != nil {
		return err
	}
	tlv, err := authPost(ctx, p.conn, "/pair-setup", "3",
		tlv8.Item{Tag: tlv8.TagMethod, Value: []byte{0x00}},
		tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x01}},
	)
	if err != nil {
		return err
	}
	p.atvSalt = tlv[tlv8.TagSalt]
	p.atvPublicKey = tlv[tlv8.TagPublicKey]
	if len(p.atvSalt) == 0 || len(p.atvPublicKey) == 0 {
		return errors.New("airplay: missing salt or public key in M2")
	}
	return nil
}

// finish runs M3..M6 with the PIN shown on screen and returns the long-term
// credentials.
func (p *pairSetup) finish(ctx context.Context, pin string) (hap.Credentials, error) {
	for len(pin) < 4 {
		pin = "0" + pin
	}

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return hap.Credentials{}, err
	}
	signingKey := ed25519.NewKeyFromSeed(seed)
	authPublic := signingKey.Public().(ed25519.PublicKey)

	srp, err := hap.NewSRPClient("Pair-Setup", pin, seed)
	if err != nil {
		return hap.Credentials{}, err
	}
	if err := srp.ProcessChallenge(p.atvSalt, p.atvPublicKey); err != nil {
		return hap.Credentials{}, err
	}

	// M3: client public key and proof.
	tlv, err := authPost(ctx, p.conn, "/pair-setup", "3",
		tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x03}},
		tlv8.Item{Tag: tlv8.TagPublicKey, Value: srp.PublicKey()},
		tlv8.Item{Tag: tlv8.TagProof, Value: srp.Proof()},
	)
	if err != nil {
		return hap.Credentials{}, err
	}
	if !srp.VerifyServerProof(tlv[tlv8.TagProof]) {
		return hap.Credentials{}, &InvalidAuth{Message: "server proof mismatch (wrong PIN?)"}
	}

	// M5: encrypted identity signature.
	deviceX := hap.HKDFExpand("Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info", srp.SessionKey())
	sessionKey := hap.HKDFExpand("Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info", srp.SessionKey())

	var deviceInfo []byte
	deviceInfo = append(deviceInfo, deviceX...)
	deviceInfo = append(deviceInfo, p.pairingID...)
	deviceInfo = append(deviceInfo, authPublic...)
	signature := ed25519.Sign(signingKey, deviceInfo)

	nameOpack, err := opack.Pack(map[string]any{"name": p.name})
	if err != nil {
		return hap.Credentials{}, err
	}
	innerTLV := tlv8.Write(
		tlv8.Item{Tag: tlv8.TagIdentifier, Value: p.pairingID},
		tlv8.Item{Tag: tlv8.TagPublicKey, Value: authPublic},
		tlv8.Item{Tag: tlv8.TagSignature, Value: signature},
		tlv8.Item{Tag: tlv8.TagName, Value: nameOpack},
	)

	cipher, err := hap.NewCipher(sessionKey, sessionKey, 8)
	if err != nil {
		return hap.Credentials{}, err
	}
	encrypted := cipher.Encrypt(innerTLV, []byte("PS-Msg05"), nil)

	tlv, err = authPost(ctx, p.conn, "/pair-setup", "3",
		tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x05}},
		tlv8.Item{Tag: tlv8.TagEncryptedData, Value: encrypted},
	)
	if err != nil {
		return hap.Credentials{}, err
	}

	// M6: decrypt device identity.
	decrypted, err := cipher.Decrypt(tlv[tlv8.TagEncryptedData], []byte("PS-Msg06"), nil)
	if err != nil {
		return hap.Credentials{}, &InvalidAuth{Message: "failed to decrypt M6"}
	}
	deviceTLV, err := tlv8.Read(decrypted)
	if err != nil {
		return hap.Credentials{}, err
	}

	return hap.Credentials{
		LTPK:     deviceTLV[tlv8.TagPublicKey],
		LTSK:     seed,
		ATVID:    deviceTLV[tlv8.TagIdentifier],
		ClientID: p.pairingID,
	}, nil
}

// verifyHAP performs HAP pair-verify (M1..M3) over POST /pair-verify with
// stored credentials, mirroring pyatv's AirPlayHapPairVerifyProcedure and
// SRPAuthHandler.verify1.
func verifyHAP(ctx context.Context, c *connection, credentials hap.Credentials) (*verifier, error) {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return nil, err
	}
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	tlv, err := authPost(ctx, c, "/pair-verify", "3",
		tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x01}},
		tlv8.Item{Tag: tlv8.TagPublicKey, Value: public},
	)
	if err != nil {
		return nil, err
	}
	serverPublic := tlv[tlv8.TagPublicKey]
	encrypted := tlv[tlv8.TagEncryptedData]
	if len(serverPublic) != 32 || len(encrypted) == 0 {
		return nil, &InvalidAuth{Message: "malformed verify response"}
	}

	shared, err := curve25519.X25519(private[:], serverPublic)
	if err != nil {
		return nil, err
	}
	sessionKey := hap.HKDFExpand("Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", shared)

	cipher, err := hap.NewCipher(sessionKey, sessionKey, 8)
	if err != nil {
		return nil, err
	}
	decrypted, err := cipher.Decrypt(encrypted, []byte("PV-Msg02"), nil)
	if err != nil {
		return nil, &InvalidAuth{Message: "failed to decrypt verify message"}
	}
	innerTLV, err := tlv8.Read(decrypted)
	if err != nil {
		return nil, err
	}
	identifier := innerTLV[tlv8.TagIdentifier]
	signature := innerTLV[tlv8.TagSignature]

	if string(identifier) != string(credentials.ATVID) {
		return nil, &InvalidAuth{Message: "incorrect device response"}
	}
	if len(credentials.LTPK) != ed25519.PublicKeySize {
		return nil, &InvalidAuth{Message: "invalid device public key in credentials"}
	}
	var info []byte
	info = append(info, serverPublic...)
	info = append(info, identifier...)
	info = append(info, public...)
	if !ed25519.Verify(ed25519.PublicKey(credentials.LTPK), info, signature) {
		return nil, &InvalidAuth{Message: "device signature verification failed"}
	}

	var deviceInfo []byte
	deviceInfo = append(deviceInfo, public...)
	deviceInfo = append(deviceInfo, credentials.ClientID...)
	deviceInfo = append(deviceInfo, serverPublic...)
	if len(credentials.LTSK) != ed25519.SeedSize {
		return nil, &InvalidAuth{Message: "invalid client secret key in credentials"}
	}
	deviceSignature := ed25519.Sign(ed25519.NewKeyFromSeed(credentials.LTSK), deviceInfo)

	responseTLV := tlv8.Write(
		tlv8.Item{Tag: tlv8.TagIdentifier, Value: credentials.ClientID},
		tlv8.Item{Tag: tlv8.TagSignature, Value: deviceSignature},
	)
	encryptedResponse := cipher.Encrypt(responseTLV, []byte("PV-Msg03"), nil)

	if _, err := authPost(ctx, c, "/pair-verify", "3",
		tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x03}},
		tlv8.Item{Tag: tlv8.TagEncryptedData, Value: encryptedResponse},
	); err != nil {
		return nil, err
	}

	return &verifier{shared: shared}, nil
}

// verifyTransient performs transient pair-setup (M1..M4 with the fixed PIN
// 3939), mirroring pyatv's AirPlayHapTransientPairVerifyProcedure. The SRP
// session key becomes the shared secret for channel keys.
func verifyTransient(ctx context.Context, c *connection) (*verifier, error) {
	if err := pairPinStart(ctx, c, "4"); err != nil {
		return nil, err
	}

	tlv, err := authPost(ctx, c, "/pair-setup", "4",
		tlv8.Item{Tag: tlv8.TagMethod, Value: []byte{0x00}},
		tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x01}},
		tlv8.Item{Tag: tlv8.TagFlags, Value: []byte{0x10}}, // transient pairing
	)
	if err != nil {
		return nil, err
	}
	atvSalt := tlv[tlv8.TagSalt]
	atvPublicKey := tlv[tlv8.TagPublicKey]
	if len(atvSalt) == 0 || len(atvPublicKey) == 0 {
		return nil, errors.New("airplay: missing salt or public key in transient M2")
	}

	srp, err := hap.NewSRPClient("Pair-Setup", transientPIN, nil)
	if err != nil {
		return nil, err
	}
	if err := srp.ProcessChallenge(atvSalt, atvPublicKey); err != nil {
		return nil, err
	}

	if _, err := authPost(ctx, c, "/pair-setup", "4",
		tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x03}},
		tlv8.Item{Tag: tlv8.TagPublicKey, Value: srp.PublicKey()},
		tlv8.Item{Tag: tlv8.TagProof, Value: srp.Proof()},
	); err != nil {
		return nil, err
	}

	return &verifier{shared: srp.SessionKey()}, nil
}

// verifyConnection performs pair-verify appropriate for the credentials and
// enables HAP encryption on the control connection when keys are available,
// mirroring pyatv's verify_connection. With hasCredentials false a transient
// session is established instead.
func verifyConnection(ctx context.Context, c *connection, credentials *hap.Credentials) (*verifier, error) {
	var (
		v   *verifier
		err error
	)
	if credentials != nil {
		v, err = verifyHAP(ctx, c, *credentials)
	} else {
		v, err = verifyTransient(ctx, c)
	}
	if err != nil {
		return nil, err
	}

	outputKey, inputKey := v.encryptionKeys(controlSalt, controlOutputInfo, controlInputInfo)
	if err := c.enableEncryption(outputKey, inputKey); err != nil {
		return nil, err
	}
	return v, nil
}
