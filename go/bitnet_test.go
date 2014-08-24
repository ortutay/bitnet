package bitnet

import (
	"encoding/hex"
	"github.com/conformal/btcec"
	"github.com/conformal/btcnet"
	"github.com/conformal/btcutil"
	"testing"
)

var (
	testnetWIF      = "cTYgHoA7GMu5wFN7QJn5fARENKnuohdJ5HUbudD2Zbe4QFNVkKKh"
	testnetAdddress = "mj4urmXZ4pjiUJnhsAXbyeNooiTBizhiFS"
)

func TestIsCompressed(t *testing.T) {
	wif, err := btcutil.DecodeWIF(testnetWIF)
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := isCompressed(
		wif.PrivKey, testnetAdddress, &btcnet.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}
	if !compressed {
		t.Errorf("Expected %v to be compressed", testnetAdddress)
	}
}

func TestSignatures(t *testing.T) {
	privKey, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), []byte("entropy"))
	buf := pubKey.SerializeCompressed()
	pubKeyHex := hex.EncodeToString(buf)
	args := GetBalanceArgs{Challenge: "xyz", PubKey: pubKeyHex}

	sig, err := GetSig(&args, privKey)
	if err != nil {
		t.Fatal(err)
	}
	args.Sig = sig

	if !CheckSig(args.Sig, &args, pubKey) {
		t.Errorf("valid signature should succeed")
	}

	privKey2, _ := btcec.PrivKeyFromBytes(btcec.S256(), []byte("entropy2"))
	sig2, err := GetSig(&args, privKey2)
	if err != nil {
		t.Fatal(err)
	}
	args.Sig = sig2
	if CheckSig(args.Sig, &args, pubKey) {
		t.Errorf("sig with different private key should fail")
	}
}
