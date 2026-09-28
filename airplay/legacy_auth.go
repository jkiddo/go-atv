package airplay

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/curve25519"

	"github.com/jkiddo/go-atv/hap"
)

const legacySRPPrime2048Hex = "AC6BDB41324A9A9BF166DE5E1389582F" +
	"AF72B6651987EE07FC3192943DB56050" +
	"A37329CBB4A099ED8193E0757767A13D" +
	"D52312AB4B03310DCD7F48A9DA04FD50" +
	"E8083969EDB767B0CF6095179A163AB3" +
	"661A05FBD5FAAAE82918A9962F0B93B8" +
	"55F97993EC975EEAA80D740ADBF4FF74" +
	"7359D041D5C33EA71D281E446B14773B" +
	"CA97B43A23FB801676BD207A436C6481" +
	"F1D2B9078717461A5B9D32E688F87748" +
	"544523B524B0D57D5EA77A2775D2ECFA" +
	"032CFBDBF52FB3786160279004E57AE6" +
	"AF874E7303CE53299CCC041C7BC308D8" +
	"2A5698F3A8D0C38271AE35F8E9DBFBB6" +
	"94B5C803D89F7AE435DE236D525F5475" +
	"9B65E372FCD68EF20FA7111F9E4AFF73"

var legacySRPPrime2048 = func() *big.Int {
	prime, ok := new(big.Int).SetString(legacySRPPrime2048Hex, 16)
	if !ok {
		panic("invalid legacy SRP prime")
	}
	return prime
}()

type legacyPairSetup struct {
	conn        *connection
	credentials hap.Credentials
}

func newLegacyCredentials() (hap.Credentials, error) {
	credentials := hap.Credentials{LTSK: make([]byte, 32), ClientID: make([]byte, 8)}
	if _, err := rand.Read(credentials.LTSK); err != nil {
		return hap.Credentials{}, err
	}
	if _, err := rand.Read(credentials.ClientID); err != nil {
		return hap.Credentials{}, err
	}
	return credentials, nil
}

func (p *legacyPairSetup) startRequest(ctx context.Context) error {
	response, err := p.conn.exchange(ctx, request{
		Method:    "POST",
		URI:       "/pair-pin-start",
		UserAgent: authUserAgent,
		Headers:   []header{{"Connection", "keep-alive"}},
	})
	if err != nil {
		return err
	}
	return errStatus(response, "POST /pair-pin-start")
}

func (p *legacyPairSetup) finish(ctx context.Context, pin string) (hap.Credentials, error) {
	for len(pin) < 4 {
		pin = "0" + pin
	}
	clientID := strings.ToUpper(hex.EncodeToString(p.credentials.ClientID))
	challenge, err := legacyPlistPost(ctx, p.conn, map[string]any{"method": "pin", "user": clientID})
	if err != nil {
		return hap.Credentials{}, err
	}
	serverPublic, publicOK := challenge["pk"].([]byte)
	salt, saltOK := challenge["salt"].([]byte)
	if !publicOK || !saltOK || len(serverPublic) == 0 || len(salt) == 0 {
		return hap.Credentials{}, errors.New("airplay: malformed legacy pair-setup challenge")
	}

	public, proof, sessionKey, expectedServerProof, err := legacySRPValues(p.credentials, clientID, pin, serverPublic, salt)
	if err != nil {
		return hap.Credentials{}, err
	}
	proofResponse, err := legacyPlistPost(ctx, p.conn, map[string]any{"pk": public, "proof": proof})
	if err != nil {
		return hap.Credentials{}, err
	}
	if serverProof, ok := proofResponse["proof"].([]byte); ok && len(serverProof) > 0 {
		if !equalBytes(serverProof, expectedServerProof) {
			return hap.Credentials{}, &InvalidAuth{Message: "legacy pair-setup server proof mismatch (wrong PIN?)"}
		}
	}

	epk, authTag, err := legacyPairSetupEncryption(p.credentials, sessionKey)
	if err != nil {
		return hap.Credentials{}, err
	}
	if _, err := legacyPlistPost(ctx, p.conn, map[string]any{"epk": epk, "authTag": authTag}); err != nil {
		return hap.Credentials{}, err
	}
	return p.credentials, nil
}

func legacyPlistPost(ctx context.Context, conn *connection, body map[string]any) (map[string]any, error) {
	raw, err := packPlist(body)
	if err != nil {
		return nil, err
	}
	response, err := conn.exchange(ctx, request{
		Method:      "POST",
		URI:         "/pair-setup-pin",
		UserAgent:   authUserAgent,
		ContentType: bplistContentType,
		Headers:     []header{{"Connection", "keep-alive"}},
		Body:        raw,
	})
	if err != nil {
		return nil, err
	}
	if err := errStatus(response, "POST /pair-setup-pin"); err != nil {
		return nil, err
	}
	return unpackPlist(response.Body)
}

func legacySRPValues(credentials hap.Credentials, username, pin string, serverPublic, salt []byte) (public, proof, sessionKey, serverProof []byte, err error) {
	if !credentials.IsLegacy() {
		return nil, nil, nil, nil, errors.New("airplay: invalid legacy credentials")
	}
	prime := legacySRPPrime2048
	generator := big.NewInt(2)
	private := new(big.Int).SetBytes(credentials.LTSK)
	clientPublic := new(big.Int).Exp(generator, private, prime)
	serverPublicInt := new(big.Int).SetBytes(serverPublic)
	if new(big.Int).Mod(serverPublicInt, prime).Sign() == 0 {
		return nil, nil, nil, nil, errors.New("airplay: invalid legacy SRP server public key")
	}

	inner := sha1.Sum([]byte(username + ":" + pin))
	x := legacyHashInt(salt, inner[:])
	k := legacyHashInt(legacyMinimalBytes(prime), legacyPad(generator, prime))
	u := legacyHashInt(legacyPad(clientPublic, prime), legacyPad(serverPublicInt, prime))

	verifier := new(big.Int).Exp(generator, x, prime)
	base := new(big.Int).Sub(serverPublicInt, new(big.Int).Mul(k, verifier))
	base.Mod(base, prime)
	exponent := new(big.Int).Add(private, new(big.Int).Mul(u, x))
	premaster := new(big.Int).Exp(base, exponent, prime)
	premasterBytes := legacyMinimalBytes(premaster)
	first := legacyHash(premasterBytes, []byte{0, 0, 0, 0})
	second := legacyHash(premasterBytes, []byte{0, 0, 0, 1})
	sessionKey = append(first, second...)

	hPrime := legacyHash(legacyMinimalBytes(prime))
	hGenerator := legacyHash(legacyMinimalBytes(generator))
	xor := make([]byte, len(hPrime))
	for index := range hPrime {
		xor[index] = hPrime[index] ^ hGenerator[index]
	}
	hUsername := legacyHash([]byte(username))
	public = legacyMinimalBytes(clientPublic)
	proof = legacyHash(xor, hUsername, salt, public, legacyMinimalBytes(serverPublicInt), sessionKey)
	serverProof = legacyHash(public, proof, sessionKey)
	return public, proof, sessionKey, serverProof, nil
}

func legacyPairSetupEncryption(credentials hap.Credentials, sessionKey []byte) (epk, authTag []byte, err error) {
	private := ed25519.NewKeyFromSeed(credentials.LTSK)
	public := private.Public().(ed25519.PublicKey)
	keyHash := sha512.Sum512(append([]byte("Pair-Setup-AES-Key"), sessionKey...))
	ivHash := sha512.Sum512(append([]byte("Pair-Setup-AES-IV"), sessionKey...))
	key := keyHash[:16]
	iv := append([]byte(nil), ivHash[:16]...)
	iv[len(iv)-1]++
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, nil, err
	}
	sealed := gcm.Seal(nil, iv, public, nil)
	return sealed[:len(public)], sealed[len(public):], nil
}

func verifyLegacy(ctx context.Context, conn *connection, credentials hap.Credentials) error {
	start, err := legacyVerifyStart(credentials)
	if err != nil {
		return err
	}
	response, err := legacyBinaryPost(ctx, conn, start)
	if err != nil {
		return err
	}
	finish, err := legacyVerifyFinish(credentials, response)
	if err != nil {
		return err
	}
	_, err = legacyBinaryPost(ctx, conn, finish)
	return err
}

func legacyBinaryPost(ctx context.Context, conn *connection, body []byte) ([]byte, error) {
	response, err := conn.exchange(ctx, request{
		Method:      "POST",
		URI:         "/pair-verify",
		UserAgent:   authUserAgent,
		ContentType: "application/octet-stream",
		Headers:     []header{{"Connection", "keep-alive"}},
		Body:        body,
	})
	if err != nil {
		return nil, err
	}
	if err := errStatus(response, "POST /pair-verify"); err != nil {
		return nil, err
	}
	return response.Body, nil
}

func legacyVerifyStart(credentials hap.Credentials) ([]byte, error) {
	if !credentials.IsLegacy() {
		return nil, errors.New("airplay: invalid legacy credentials")
	}
	public, err := curve25519.X25519(credentials.LTSK, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	authPublic := ed25519.NewKeyFromSeed(credentials.LTSK).Public().(ed25519.PublicKey)
	body := []byte{1, 0, 0, 0}
	body = append(body, public...)
	body = append(body, authPublic...)
	return body, nil
}

func legacyVerifyFinish(credentials hap.Credentials, response []byte) ([]byte, error) {
	if !credentials.IsLegacy() {
		return nil, errors.New("airplay: invalid legacy credentials")
	}
	if len(response) < curve25519.PointSize {
		return nil, &InvalidAuth{Message: "malformed legacy pair-verify response"}
	}
	serverPublic := response[:curve25519.PointSize]
	serverData := response[curve25519.PointSize:]
	clientPublic, err := curve25519.X25519(credentials.LTSK, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(credentials.LTSK, serverPublic)
	if err != nil {
		return nil, err
	}
	keyHash := sha512.Sum512(append([]byte("Pair-Verify-AES-Key"), shared...))
	ivHash := sha512.Sum512(append([]byte("Pair-Verify-AES-IV"), shared...))
	block, err := aes.NewCipher(keyHash[:16])
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, ivHash[:16])
	discard := make([]byte, len(serverData))
	stream.XORKeyStream(discard, serverData)
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(credentials.LTSK), append(clientPublic, serverPublic...))
	encryptedSignature := make([]byte, len(signature))
	stream.XORKeyStream(encryptedSignature, signature)
	return append([]byte{0, 0, 0, 0}, encryptedSignature...), nil
}

func legacyHash(parts ...[]byte) []byte {
	hash := sha1.New()
	for _, part := range parts {
		_, _ = hash.Write(part)
	}
	return hash.Sum(nil)
}

func legacyHashInt(parts ...[]byte) *big.Int {
	return new(big.Int).SetBytes(legacyHash(parts...))
}

func legacyPad(value, prime *big.Int) []byte {
	bytes := legacyMinimalBytes(value)
	width := len(legacyMinimalBytes(prime))
	if len(bytes) >= width {
		return bytes
	}
	padded := make([]byte, width)
	copy(padded[width-len(bytes):], bytes)
	return padded
}

func legacyMinimalBytes(value *big.Int) []byte {
	bytes := value.Bytes()
	if len(bytes) == 0 {
		return []byte{0}
	}
	return bytes
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func legacyCredentialTypeError(features Features, credentials *hap.Credentials) error {
	if credentials == nil {
		return errors.New("airplay: receiver requires pairing")
	}
	if features != 0 && !features.isVersion2() && !credentials.IsLegacy() {
		return fmt.Errorf("airplay: AirPlay v1 receiver has incompatible HAP credentials; pair again")
	}
	if (features == 0 || features.isVersion2()) && credentials.IsLegacy() {
		return fmt.Errorf("airplay: AirPlay v2 receiver has incompatible legacy credentials; pair again")
	}
	return nil
}
