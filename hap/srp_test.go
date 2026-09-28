package hap

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vector generated with srptools (the SRP library pyatv uses) using
// SHA-512 and the RFC 5054 3072-bit group:
//
//	username    = "Pair-Setup"
//	password    = "1234"
//	salt        = 000102030405060708090a0b0c0d0e0f
//	client priv = 0x11 * 32
//	server priv = 0x22 * 32
const (
	srpVectorSalt = "000102030405060708090a0b0c0d0e0f"
	srpVectorA    = "c95341372ca4d0b469f87c0ae37bda635713223b577ef5e8d64a959a54e5395722fea50e71bbd44306055760924a64885805ae13545fcfc7e65f4e7b75c765a112d267f79bffb8353d96ae81cfa64ca7eb687a5dba4cf223b21e1362489ca3e056254b25f610c00643490ea19944f6d3d0872bdcc5fc338bebc8936f30b695924e117f364a4cfc3898eeaa1a4bb98957df8eb046eba3cf42558138ca616a1dc7991426292dd258693bbd4c11816e3064e4a7c536f7255ae61735db25e3cf0349eb8b3e9848d0aa572b0f809d8983f1b280581aba96104422fcf088b698f8d899115a5653cc473e87f5e45552a5a126c8b7fc273bd2cd12bfb15ff3501a572b17608f16c33f6e971081f3af1be37a0a96748f60d204e935f6a5d2a71303aea434b45bcb9ab6b4444208d3fdf7a00c07a3ba2a09b56b578170c78ba1573ca2692406ba8d461e43bb3d160f0024a388d7234236537e29c3604f666c69d7244eae29a0e8b9fa5ee490890e5892973fa535707fbe8f06e90dcbb99c7b39b5eb2b45fb"
	srpVectorB    = "28a99552d3331b6a630094bf3ab909b64d178727f8faa5da9d7eda140ee7f0738a7948230bb5637fd01df4b9b484d3f7bb4670fe92bc0d7356c72e8adea978a16e81c5912652a80791cab85f29e8cfb1b2c26059cb4fc5b79cb671f30363d613b4e3f8b6248511249e3f626f52cf375ca8c538cd5b90bf07eab7902a9fbc8712200d4ffa1d5e08f6c379e971adf9683b29fe84b6d6ea9e6a12eafb2da9088e32b967895d17346809c4ae5f1ae7810632d43c723a361694a154b8d1bdb1abd5a86ddf2d8ec134c0e6099a7cf5e40b5d0eda73d488554fdaff8f3171b109c525ce0f8d3112a134295642aae1250e789bb1f059764b7449f9a74b7e865e2fd55949d85456141a4d810a11343badbd5488fdf450d367634735d48e81accdfda0dba04b1e9389f3fa6d8406fb3f14e6c0014c75e5019080a0402010969c9fdca0a2a9acfe31bfe861d39ba5bf6582bdae97041b0d45a89b3bdc393e75dc1a2c73c263b2fd6398172038d99eedbbb2a98690543ce6f514e63284be8280ab23964c9222"
	srpVectorK    = "2f626fe5ae691b367fc11f23f0f14dcaf752d8af654c656c30a67985318e92f7ba1196c05c4f7747c0294c009cba4de3d4bd9c3c3e379fe3a7dcf621ac7167ca"
	srpVectorM1   = "07e0a5ba1ad1f5ba640c21060bd63491bf81346f5227b45af783934d01470055dd06a6019391d1e6a02127ecc456f3b3b870bd3e36b7a0bf5360a8f8c3b2da12"
	srpVectorM2   = "1dd6aea43546d37b835ab8590beaf2210d6233ab74613e01079076d467aac30effb9f4ff57c6f6e5692cbff741613c5ba58e7c44b94bf80c70204edc13867355"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSRPClientAgainstSrptoolsVector(t *testing.T) {
	private := bytes.Repeat([]byte{0x11}, 32)
	client, err := NewSRPClient("Pair-Setup", "1234", private)
	if err != nil {
		t.Fatal(err)
	}

	if got := hex.EncodeToString(client.PublicKey()); got != srpVectorA {
		t.Errorf("public key A mismatch:\n got %s\nwant %s", got, srpVectorA)
	}

	salt := mustHex(t, srpVectorSalt)
	serverPublic := mustHex(t, srpVectorB)
	if err := client.ProcessChallenge(salt, serverPublic); err != nil {
		t.Fatal(err)
	}

	if got := hex.EncodeToString(client.SessionKey()); got != srpVectorK {
		t.Errorf("session key K mismatch:\n got %s\nwant %s", got, srpVectorK)
	}
	if got := hex.EncodeToString(client.Proof()); got != srpVectorM1 {
		t.Errorf("proof M1 mismatch:\n got %s\nwant %s", got, srpVectorM1)
	}
	if !client.VerifyServerProof(mustHex(t, srpVectorM2)) {
		t.Error("server proof M2 not accepted")
	}
	if client.VerifyServerProof([]byte("bogus")) {
		t.Error("bogus server proof accepted")
	}
}

func TestSRPClientRejectsZeroServerKey(t *testing.T) {
	client, err := NewSRPClient("Pair-Setup", "1234", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ProcessChallenge([]byte{1, 2, 3}, []byte{0}); err == nil {
		t.Error("expected error for zero server public key")
	}
}
