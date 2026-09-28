package companion

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

const pairingDataKey = "_pd"

// pairingData extracts and parses the TLV8 pairing payload from an auth
// frame response, surfacing HAP errors.
func pairingData(message map[string]any) (map[byte][]byte, error) {
	raw, ok := message[pairingDataKey].([]byte)
	if !ok || len(raw) == 0 {
		return nil, errors.New("companion: no pairing data in message")
	}
	tlv, err := tlv8.Read(raw)
	if err != nil {
		return nil, err
	}
	if errValue, ok := tlv[tlv8.TagError]; ok && len(errValue) > 0 {
		if errValue[0] == tlv8.ErrorAuthentication {
			return nil, &InvalidAuth{Message: "device rejected authentication"}
		}
		return nil, fmt.Errorf("companion: pairing error code %d", errValue[0])
	}
	return tlv, nil
}

// pairSetup implements HAP pair-setup (M1..M6) over Companion frames,
// mirroring pyatv's CompanionPairSetupProcedure. The PIN is displayed on the
// Apple TV after startRequest.
type pairSetup struct {
	session   *session
	name      string
	pairingID []byte

	atvSalt      []byte
	atvPublicKey []byte
}

// startRequest sends M1, which makes the Apple TV display a PIN.
func (p *pairSetup) startRequest(ctx context.Context) error {
	ctx, cancel := withDefaultTimeout(ctx)
	defer cancel()

	resp, err := p.session.exchangeAuth(ctx, FramePSStart, map[string]any{
		pairingDataKey: tlv8.Write(
			tlv8.Item{Tag: tlv8.TagMethod, Value: []byte{0x00}},
			tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x01}},
		),
		"_pwTy": int64(1),
	})
	if err != nil {
		return err
	}
	tlv, err := pairingData(resp)
	if err != nil {
		return err
	}
	p.atvSalt = tlv[tlv8.TagSalt]
	p.atvPublicKey = tlv[tlv8.TagPublicKey]
	if len(p.atvSalt) == 0 || len(p.atvPublicKey) == 0 {
		return errors.New("companion: missing salt or public key in M2")
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
	m3Ctx, cancel := withDefaultTimeout(ctx)
	resp, err := p.session.exchangeAuth(m3Ctx, FramePSNext, map[string]any{
		pairingDataKey: tlv8.Write(
			tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x03}},
			tlv8.Item{Tag: tlv8.TagPublicKey, Value: srp.PublicKey()},
			tlv8.Item{Tag: tlv8.TagProof, Value: srp.Proof()},
		),
		"_pwTy": int64(1),
	})
	cancel()
	if err != nil {
		return hap.Credentials{}, err
	}
	tlv, err := pairingData(resp)
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

	m5Ctx, cancel := withDefaultTimeout(ctx)
	resp, err = p.session.exchangeAuth(m5Ctx, FramePSNext, map[string]any{
		pairingDataKey: tlv8.Write(
			tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x05}},
			tlv8.Item{Tag: tlv8.TagEncryptedData, Value: encrypted},
		),
		"_pwTy": int64(1),
	})
	cancel()
	if err != nil {
		return hap.Credentials{}, err
	}
	tlv, err = pairingData(resp)
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

// pairVerify implements HAP pair-verify over Companion frames and returns the
// session encryption keys, mirroring pyatv's CompanionPairVerifyProcedure.
func pairVerify(ctx context.Context, s *session, credentials hap.Credentials) (outputKey, inputKey []byte, err error) {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return nil, nil, err
	}
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	m1Ctx, cancel := withDefaultTimeout(ctx)
	resp, err := s.exchangeAuth(m1Ctx, FramePVStart, map[string]any{
		pairingDataKey: tlv8.Write(
			tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x01}},
			tlv8.Item{Tag: tlv8.TagPublicKey, Value: public},
		),
		"_auTy": int64(4),
	})
	cancel()
	if err != nil {
		return nil, nil, err
	}
	tlv, err := pairingData(resp)
	if err != nil {
		return nil, nil, err
	}
	serverPublic := tlv[tlv8.TagPublicKey]
	encrypted := tlv[tlv8.TagEncryptedData]
	if len(serverPublic) != 32 || len(encrypted) == 0 {
		return nil, nil, &InvalidAuth{Message: "malformed verify response"}
	}

	shared, err := curve25519.X25519(private[:], serverPublic)
	if err != nil {
		return nil, nil, err
	}
	sessionKey := hap.HKDFExpand("Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", shared)

	cipher, err := hap.NewCipher(sessionKey, sessionKey, 8)
	if err != nil {
		return nil, nil, err
	}
	decrypted, err := cipher.Decrypt(encrypted, []byte("PV-Msg02"), nil)
	if err != nil {
		return nil, nil, &InvalidAuth{Message: "failed to decrypt verify message"}
	}
	innerTLV, err := tlv8.Read(decrypted)
	if err != nil {
		return nil, nil, err
	}
	identifier := innerTLV[tlv8.TagIdentifier]
	signature := innerTLV[tlv8.TagSignature]

	if string(identifier) != string(credentials.ATVID) {
		return nil, nil, &InvalidAuth{Message: "incorrect device response"}
	}
	if len(credentials.LTPK) != ed25519.PublicKeySize {
		return nil, nil, &InvalidAuth{Message: "invalid device public key in credentials"}
	}
	var info []byte
	info = append(info, serverPublic...)
	info = append(info, identifier...)
	info = append(info, public...)
	if !ed25519.Verify(ed25519.PublicKey(credentials.LTPK), info, signature) {
		return nil, nil, &InvalidAuth{Message: "device signature verification failed"}
	}

	var deviceInfo []byte
	deviceInfo = append(deviceInfo, public...)
	deviceInfo = append(deviceInfo, credentials.ClientID...)
	deviceInfo = append(deviceInfo, serverPublic...)
	if len(credentials.LTSK) != ed25519.SeedSize {
		return nil, nil, &InvalidAuth{Message: "invalid client secret key in credentials"}
	}
	deviceSignature := ed25519.Sign(ed25519.NewKeyFromSeed(credentials.LTSK), deviceInfo)

	responseTLV := tlv8.Write(
		tlv8.Item{Tag: tlv8.TagIdentifier, Value: credentials.ClientID},
		tlv8.Item{Tag: tlv8.TagSignature, Value: deviceSignature},
	)
	encryptedResponse := cipher.Encrypt(responseTLV, []byte("PV-Msg03"), nil)

	m3Ctx, cancel := withDefaultTimeout(ctx)
	resp, err = s.exchangeAuth(m3Ctx, FramePVNext, map[string]any{
		pairingDataKey: tlv8.Write(
			tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x03}},
			tlv8.Item{Tag: tlv8.TagEncryptedData, Value: encryptedResponse},
		),
	})
	cancel()
	if err != nil {
		return nil, nil, err
	}
	if _, err := pairingData(resp); err != nil {
		return nil, nil, err
	}

	outputKey = hap.HKDFExpand("", "ClientEncrypt-main", shared)
	inputKey = hap.HKDFExpand("", "ServerEncrypt-main", shared)
	return outputKey, inputKey, nil
}
