package bitnet

import (
	"encoding/hex"
	"github.com/conformal/btcec"
	"github.com/conformal/btcnet"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcutil/hdkeychain"
	"strings"
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

func TestValidateMessages(t *testing.T) {
	master, err := genMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	pubKeyHex, err := pubKeyAsHex(master)
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := master.ECPrivKey()
	if err != nil {
		t.Fatal(err)
	}

	var validDatetime Message
	validDatetime.Plaintext.AddHeader("datetime", "1985-04-12T23:20:50.52Z")
	validDatetime.Plaintext.AddHeader("expires-datetime", "1985-04-12T23:20:50.52Z")

	var invalidDatetime Message
	invalidDatetime.Plaintext.AddHeader("datetime", "123")

	var validPubKey Message
	validPubKey.Plaintext.AddHeader("sender-pubkey", pubKeyHex)
	validPubKey.Plaintext.AddHeader("receiver-pubkey", pubKeyHex)
	validPubKey.Plaintext.AddHeader("expires-pubkey", pubKeyHex)

	var invalidSenderPubKey Message
	invalidSenderPubKey.Plaintext.AddHeader("receiver-pubkey", pubKeyHex)
	invalidSenderPubKey.Plaintext.AddHeader("sender-pubkey", "deadbeaf")

	validSig := Message{
		Plaintext: Section{Body: "some message content"},
		Encrypted: "aDkje840klD/ad",
	}
	validSig.Plaintext.AddHeader("datetime", "1985-04-12T23:20:50.52Z")
	validSig.Plaintext.AddHeader("sender-pubkey", pubKeyHex)
	validSig.Plaintext.AddHeader("type", "coinjoin")
	validSig.Plaintext.AddHeader("-coinjoin-header", "additional data")
	sig, err := GetSig(&validSig, privKey)
	if err != nil {
		t.Fatal(err)
	}
	validSig.Plaintext.AddHeader("sender-sig", sig)

	invalidSig := Message{
		Plaintext: Section{Body: "some message content"},
		Encrypted: "aDkje840klD/ad",
	}
	invalidSig.Plaintext.AddHeader("datetime", "1985-04-12T23:20:50.52Z")
	invalidSig.Plaintext.AddHeader("sender-pubkey", pubKeyHex)
	invalidSig.Plaintext.AddHeader("type", "coinjoin")
	invalidSig.Plaintext.AddHeader("-coinjoin-header", "additional data")
	invalidSig.Plaintext.AddHeader("sender-sig", "ajkD28/a98E")

	var tooLarge Message
	tooLarge.Plaintext.Body = strings.Repeat(".", 100001)

	var tests = []struct {
		want    string
		message *Message
	}{
		{
			want:    "",
			message: &validDatetime,
		},
		{
			want:    `invalid datetime: parsing time "123" as "2006-01-02T15:04:05Z07:00": cannot parse "123" as "2006"`,
			message: &invalidDatetime,
		},
		{
			want:    "",
			message: &validPubKey,
		},
		{
			want:    "invalid sender-pubkey",
			message: &invalidSenderPubKey,
		},
		{
			want:    "",
			message: &validSig,
		},
		{
			want:    `invalid sig/pubkey: "ajkD28/a98E" "02df5e440f8825d851a7e2bc8f43e14e79f32836d6710c5efbb2ed9c81ca811b02"`,
			message: &invalidSig,
		},
		{
			want:    "message size exceeds maximum: 100001 > 100000",
			message: &tooLarge,
		},
	}

	for _, test := range tests {
		err := test.message.Validate()
		if test.want == "" && err != nil {
			t.Errorf("Validate()\nwant: %v\n got: %v", test.want, err)
		}
		if test.want != "" && err.Error() != test.want {
			t.Errorf("Validate()\nwant: %v\n got: %v", test.want, err)
		}
	}
}

func genMasterKey() (*hdkeychain.ExtendedKey, error) {
	key, err := hdkeychain.NewMaster([]byte("some seed data 1234"))
	if err != nil {
		return nil, err
	}
	key.SetNet(&btcnet.TestNet3Params)
	return key, nil
}

func pubKeyAsHex(key *hdkeychain.ExtendedKey) (string, error) {
	pubKey, err := key.ECPubKey()
	if err != nil {
		return "", err
	}
	buf := pubKey.SerializeCompressed()
	pubKeyHex := hex.EncodeToString(buf)
	return pubKeyHex, nil
}
