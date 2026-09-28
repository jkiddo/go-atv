package airplay

import (
	"encoding/hex"
	"testing"

	"github.com/jkiddo/go-atv/hap"
)

const (
	legacyTestCredentials  = "75fbeec773cfc563:8f06696f2542d70df59286c761695c485f815be3d152849e1361282d46ab1493"
	legacyTestServerPublic = "8817e16146c7d12b45e810b0bf190a4ccb25d9a20a8d0504d874daa8db5574c51c8b33703a95c00bdbe99c8c3745d1ef1b38e538edfd98e09ec029effe6f28b3b54a1bd41c28d8f33da6f5ac9327bfce9a66869dae645b5cbd2c6b8fbe14a30ad4f8598154f2ef7f4f52cee3e3042a69780463c26bbb764870eb1995b26a2a4ade05564836d788baf07469a143c410ea9d07a068eb790b2b0aa5b86c990636814e3fa1a899ceba1af45b211ca4bd3b5b66ffaf16051a4f851e120476054258f257b8521a068907ad5e9c7220d5cef9aa072dec9edb7ebf633cad4d52d105cf58440f17e236332b0b26539851a879e9ac8d3c2da4c590785468e590296d39d737"
	legacyTestSalt         = "fca6dcb6b83a7c716a692f806e915954"
	legacyTestPublic       = "0819b6ba7feead4753809314e2b4c5db9109f737a0fc70b758342b6bbf536fae4e40cf94607588abb17c2076030cc00c2c1fa5fc3b3dfe8aa1ec2f23f74d917c0792fbf02f131377dfb8ae2a1656ceaa0a36bb3ab752586e1af17e1d5ef24ce083f3f9298d0be761f26c0d48af86510bf9aac7940cf90bff6bd214cf34b5536856c80f076cfbe06fd69af9d6a07a6d3ac580dfffc8a40b9730575a16c5046cd73321a944880dcf9fac952afc7ffd2d135e57ec208b11cef22b734f331ad4d8c9a737b588f7b30bd5210c65cae2ba0226f69ce7b505771faa63af89ed2f9e8325d7d5f3a2da7412f9d837860632d7f81b7fa5e09dd85e1539184070c0fa8433c2"
	legacyTestProof        = "fc6286910833d3e7ae0631d47ddbb0f492ef85b8"
	legacyTestServerProof  = "84a88548b12bce122ad1cea6caff312630edcf27"
	legacyTestEPK          = "ff07fc8520d10728e6f2ab0a0245dfa20709b5d1ae5f9a19328b0663ba9414f2"
	legacyTestAuthTag      = "52a92f8712c6ea417f3adb3d03d8e563"
	legacyVerifyStep1      = "01000000891bae9f581f68f9c9933c4f713fbb5b9de639ec7df5d0a4fd4f342f1c21aa6a5e9d1e843302d6265b8c48dd169e273460e567916b0b36280ac071001118f6b2"
	legacyVerifyResponse   = "3221371da9f00d035955caa912455fd2acee68117b557f25e39168746af4b631cfab7b2c6d0b58e96cc10af884f5a4cdef8063858a9d9c04e866743cf4b77b4be50de1352ab4ff2691a1a7afd8c1341475b4170ac50455973b7fcf3c24324fa9"
	legacyVerifyStep2      = "00000000a1f91acf64aacb185684080b817103b423816ad63b7f5e001f62337b4cc4b3b92c1474959930b7c2a59d0004814300580459d06fc6cc6441bd82bac72a5c5cc7"
)

func TestLegacyPairSetupMatchesPyATVVectors(t *testing.T) {
	credentials, err := hap.ParseCredentials(legacyTestCredentials)
	if err != nil {
		t.Fatal(err)
	}
	public, proof, sessionKey, serverProof, err := legacySRPValues(
		credentials,
		"75FBEEC773CFC563",
		"2271",
		decodeHex(t, legacyTestServerPublic),
		decodeHex(t, legacyTestSalt),
	)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "public", public, legacyTestPublic)
	assertHex(t, "proof", proof, legacyTestProof)
	assertHex(t, "server proof", serverProof, legacyTestServerProof)

	epk, authTag, err := legacyPairSetupEncryption(credentials, sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "epk", epk, legacyTestEPK)
	assertHex(t, "auth tag", authTag, legacyTestAuthTag)
}

func TestLegacyPairVerifyMatchesPyATVVectors(t *testing.T) {
	credentials, err := hap.ParseCredentials(legacyTestCredentials)
	if err != nil {
		t.Fatal(err)
	}
	start, err := legacyVerifyStart(credentials)
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "verify step 1", start, legacyVerifyStep1)
	finish, err := legacyVerifyFinish(credentials, decodeHex(t, legacyVerifyResponse))
	if err != nil {
		t.Fatal(err)
	}
	assertHex(t, "verify step 2", finish, legacyVerifyStep2)
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func assertHex(t *testing.T, name string, actual []byte, expected string) {
	t.Helper()
	if encoded := hex.EncodeToString(actual); encoded != expected {
		t.Fatalf("%s = %s, want %s", name, encoded, expected)
	}
}
