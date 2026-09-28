package hap

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"math/big"
)

// SRP client for HAP pair-setup: SRP-6a with the RFC 5054 3072-bit group and
// SHA-512. Byte-level encodings (minimal big-endian integers, padding only
// for k and u) deliberately mirror the srptools library that pyatv uses, as
// that behaviour is what Apple TVs are proven to accept.

// RFC 5054 3072-bit group.
const srpPrime3072Hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
	"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

const srpGenerator3072 = 5

// SRPClient holds client-side SRP session state.
type SRPClient struct {
	prime      *big.Int
	generator  *big.Int
	multiplier *big.Int // k = H(N | PAD(g))
	username   string
	password   string

	private *big.Int // a
	public  *big.Int // A

	sessionKey []byte // K = H(S)
	proofM1    []byte // M1
	proofM2    []byte // M2 = H(A | M1 | K)
}

// NewSRPClient creates an SRP client for the given identity. If private is
// nil a random 256-bit client private value is generated.
func NewSRPClient(username, password string, private []byte) (*SRPClient, error) {
	prime, ok := new(big.Int).SetString(srpPrime3072Hex, 16)
	if !ok {
		panic("invalid SRP prime")
	}
	generator := big.NewInt(srpGenerator3072)

	if private == nil {
		private = make([]byte, 32)
		if _, err := rand.Read(private); err != nil {
			return nil, err
		}
	}
	a := new(big.Int).SetBytes(private)

	c := &SRPClient{
		prime:     prime,
		generator: generator,
		username:  username,
		password:  password,
		private:   a,
	}
	c.multiplier = c.hashToInt(minimalBytes(prime), c.pad(generator))
	c.public = new(big.Int).Exp(generator, a, prime)
	return c, nil
}

// PublicKey returns A as minimal big-endian bytes (srptools encoding).
func (c *SRPClient) PublicKey() []byte {
	return minimalBytes(c.public)
}

// ProcessChallenge consumes the server's salt and public key B, computing the
// session key and proofs.
func (c *SRPClient) ProcessChallenge(salt, serverPublic []byte) error {
	B := new(big.Int).SetBytes(serverPublic)
	if new(big.Int).Mod(B, c.prime).Sign() == 0 {
		return errors.New("srp: invalid server public key")
	}

	// x = H(salt | H(I ":" P))
	inner := sha512.Sum512([]byte(c.username + ":" + c.password))
	x := c.hashToInt(salt, inner[:])

	// u = H(PAD(A) | PAD(B))
	u := c.hashToInt(c.pad(c.public), c.pad(B))

	// S = (B - k*g^x) ^ (a + u*x) mod N
	v := new(big.Int).Exp(c.generator, x, c.prime) // v = g^x
	base := new(big.Int).Sub(B, new(big.Int).Mul(c.multiplier, v))
	base.Mod(base, c.prime)
	exponent := new(big.Int).Add(c.private, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(base, exponent, c.prime)

	// K = H(S)
	K := sha512.Sum512(minimalBytes(S))
	c.sessionKey = K[:]

	// M1 = H(H(N) xor H(g) | H(I) | salt | A | B | K)
	hN := c.hashToInt(minimalBytes(c.prime))
	hG := c.hashToInt(minimalBytes(c.generator))
	hI := c.hashToInt([]byte(c.username))
	m1 := sha512.New()
	m1.Write(minimalBytes(new(big.Int).Xor(hN, hG)))
	m1.Write(minimalBytes(hI))
	m1.Write(salt)
	m1.Write(minimalBytes(c.public))
	m1.Write(minimalBytes(B))
	m1.Write(c.sessionKey)
	c.proofM1 = m1.Sum(nil)

	// M2 = H(A | M1 | K)
	m2 := sha512.New()
	m2.Write(minimalBytes(c.public))
	m2.Write(c.proofM1)
	m2.Write(c.sessionKey)
	c.proofM2 = m2.Sum(nil)

	return nil
}

// Proof returns the client proof M1. Valid after ProcessChallenge.
func (c *SRPClient) Proof() []byte { return c.proofM1 }

// SessionKey returns the shared session key K. Valid after ProcessChallenge.
func (c *SRPClient) SessionKey() []byte { return c.sessionKey }

// VerifyServerProof checks the server's proof M2.
func (c *SRPClient) VerifyServerProof(proof []byte) bool {
	return c.proofM2 != nil && hmac.Equal(proof, c.proofM2)
}

// pad left-pads the minimal encoding of v with zeros to the prime's width.
func (c *SRPClient) pad(v *big.Int) []byte {
	width := len(minimalBytes(c.prime))
	b := minimalBytes(v)
	if len(b) >= width {
		return b
	}
	padded := make([]byte, width)
	copy(padded[width-len(b):], b)
	return padded
}

// hashToInt hashes the concatenation of args with SHA-512 and interprets the
// digest as a big-endian integer (srptools' hash()).
func (c *SRPClient) hashToInt(args ...[]byte) *big.Int {
	h := sha512.New()
	for _, arg := range args {
		h.Write(arg)
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

// minimalBytes returns the minimal big-endian representation of v, with a
// single zero byte for zero (srptools' int_to_bytes()).
func minimalBytes(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) == 0 {
		return []byte{0}
	}
	return b
}
