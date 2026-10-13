package simulator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"math/big"
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

// labPIN is a connection-scoped legacy SRP server for the explicit lab mode.
// It never uses or exports real receiver credentials.
type labPIN struct {
	user                      string
	salt                      []byte
	private, verifier, public *big.Int
	key                       []byte
	phase                     int
}

func pinHash(parts ...[]byte) []byte {
	h := sha1.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
func pinInt(parts ...[]byte) *big.Int { return new(big.Int).SetBytes(pinHash(parts...)) }
func pinPad(n *big.Int) []byte        { return n.FillBytes(make([]byte, 256)) }
func (r *Receiver) pinExchange(s **labPIN, props map[string]any) (map[string]any, error) {
	fail := func() (map[string]any, error) { *s = nil; return nil, errors.New("invalid lab PIN exchange") }
	n, g := legacySRPPrime2048, big.NewInt(2)
	if user, ok := props["user"].(string); ok {
		if *s != nil || len(user) == 0 || len(user) > 128 || props["method"] != "pin" {
			return fail()
		}
		salt, priv := make([]byte, 16), make([]byte, 32)
		rand.Read(salt)
		rand.Read(priv)
		x := pinInt(salt, pinHash([]byte(user+":"+r.config.PIN)))
		v := new(big.Int).Exp(g, x, n)
		b := new(big.Int).SetBytes(priv)
		pub := new(big.Int).Mul(pinInt(n.Bytes(), pinPad(g)), v)
		pub.Add(pub, new(big.Int).Exp(g, b, n))
		pub.Mod(pub, n)
		*s = &labPIN{user: user, salt: salt, private: b, verifier: v, public: pub, phase: 1}
		return map[string]any{"pk": pub.Bytes(), "salt": salt}, nil
	}
	if *s == nil {
		return fail()
	}
	state := *s
	if state.phase == 1 {
		pk, ok := props["pk"].([]byte)
		proof, pok := props["proof"].([]byte)
		if !ok || !pok || len(pk) == 0 || len(pk) > 256 || len(proof) != 20 {
			return fail()
		}
		a := new(big.Int).SetBytes(pk)
		if a.Sign() == 0 || a.Cmp(n) >= 0 {
			return fail()
		}
		u := pinInt(pinPad(a), pinPad(state.public))
		if u.Sign() == 0 {
			return fail()
		}
		base := new(big.Int).Mul(a, new(big.Int).Exp(state.verifier, u, n))
		base.Mod(base, n)
		shared := new(big.Int).Exp(base, state.private, n).Bytes()
		key := append(pinHash(shared, []byte{0, 0, 0, 0}), pinHash(shared, []byte{0, 0, 0, 1})...)
		xor := pinHash(n.Bytes())
		hg := pinHash(g.Bytes())
		for i := range xor {
			xor[i] ^= hg[i]
		}
		want := pinHash(xor, pinHash([]byte(state.user)), state.salt, a.Bytes(), state.public.Bytes(), key)
		if subtle.ConstantTimeCompare(proof, want) != 1 {
			return fail()
		}
		state.key = key
		state.phase = 2
		return map[string]any{"proof": pinHash(a.Bytes(), proof, key)}, nil
	}
	if state.phase != 2 {
		return fail()
	}
	epk, ok := props["epk"].([]byte)
	tag, tok := props["authTag"].([]byte)
	if !ok || !tok || len(epk) != 32 || len(tag) != 16 {
		return fail()
	}
	key := sha512.Sum512(append([]byte("Pair-Setup-AES-Key"), state.key...))
	iv := sha512.Sum512(append([]byte("Pair-Setup-AES-IV"), state.key...))
	nonce := append([]byte(nil), iv[:16]...)
	nonce[15]++
	block, _ := aes.NewCipher(key[:16])
	gcm, _ := cipher.NewGCMWithNonceSize(block, 16)
	pub, e := gcm.Open(nil, nonce, append(append([]byte(nil), epk...), tag...), nil)
	if e != nil {
		return fail()
	}
	r.mu.Lock()
	if r.controllers == nil {
		r.controllers = make(map[string]bool)
	}
	r.controllers[string(pub)] = true
	r.mu.Unlock()
	nonce[15]++
	server := ed25519.NewKeyFromSeed(r.credentials.LTSK).Public().(ed25519.PublicKey)
	sealed := gcm.Seal(nil, nonce, server, nil)
	clear(state.key)
	*s = nil
	return map[string]any{"epk": sealed[:32], "authTag": sealed[32:]}, nil
}
