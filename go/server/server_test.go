package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"bitbucket.org/ortutay/bitnet"
	"bitbucket.org/ortutay/bitnet/util"

	"github.com/conformal/btcchain"
	"github.com/conformal/btcnet"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcutil/hdkeychain"
	"github.com/conformal/btcwire"
	"github.com/ortutay/helloblock"
)

var (
	compressedKeySize   = 33
	uncompressedKeySize = 65
)

var (
	testnetWIF      = "cTYgHoA7GMu5wFN7QJn5fARENKnuohdJ5HUbudD2Zbe4QFNVkKKh"
	testnetAdddress = "mj4urmXZ4pjiUJnhsAXbyeNooiTBizhiFS"
)

const btcAddr = "mj4urmXZ4pjiUJnhsAXbyeNooiTBizhiFS"

func TestBuyTokens(t *testing.T) {
	dir := initTempAppDir(t)
	defer os.RemoveAll(dir)
	service := NewBitnetServiceOnHelloBlock(bitnet.BitcoinAddress(btcAddr))

	rawTx, err := genTestRawTx(btcAddr)
	if err != nil {
		t.Fatal(err)
	}

	master, err := genMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	pubKeyHex, err := pubKeyAsHex(master)

	args := bitnet.BuyTokensArgs{
		RawTx:  rawTx,
		PubKey: pubKeyHex,
	}

	fmt.Printf("args: %v\n", rawTx, args)
	var reply bitnet.BuyTokensReply
	if err := service.BuyTokens(nil, &args, &reply); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("reply: %v\n", reply)
}

func TestClaimTokens(t *testing.T) {
	// defer os.RemoveAll(initTempAppDir(t))
	initTempAppDir(t)
	service := NewBitnetServiceOnHelloBlock(bitnet.BitcoinAddress(btcAddr))

	// 1) Get challenge string
	var challengeReply bitnet.ChallengeReply
	if err := service.Challenge(nil, &bitnet.ChallengeArgs{}, &challengeReply); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("challenge reply: %v\n", challengeReply)

	// 2) Claim the tokens by signing with an address holding BTC
	privKeyStr := testnetWIF
	inputAddressStr := testnetAdddress
	wif, err := btcutil.DecodeWIF(privKeyStr)
	if err != nil {
		t.Fatal(err)
	}
	privKey := wif.PrivKey

	// Tokens destination
	master, err := genMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	pubKeyHex, err := pubKeyAsHex(master)
	_ = pubKeyHex
	if err != nil {
		t.Fatal(err)
	}

	// Construct arguments
	claimArgs := bitnet.ClaimTokensArgs{
		Challenge:      challengeReply.Challenge,
		BitcoinAddress: testnetAdddress,
		PubKey:         pubKeyHex,
	}

	// Sign with BTC priv key, *not* tokens destination priv key
	sig, err := bitnet.SignArgsBitcoin(
		&claimArgs, privKey, inputAddressStr, &btcnet.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}
	claimArgs.Sig = sig

	var claimReply bitnet.ClaimTokensReply

	if err := service.ClaimTokens(nil, &claimArgs, &claimReply); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("claim reply: %v\n", claimReply)
}

func genTestRawTx(toAddressStr string) (string, error) {
	// Get testnet privkey from helloblock.io
	data, err := helloblock.Faucet(1)
	if err != nil {
		return "", err
	}

	// Collect tx variables
	txid := data.Unspents[0].TxHash
	privKeyStr := data.PrivateKeyWIF
	inputAddressStr := data.Unspents[0].Address
	inputScriptHex := data.Unspents[0].ScriptPubKey
	vinIdx := data.Unspents[0].Index
	fee := 1000
	value := data.Unspents[0].Value - fee

	// Make the tx
	tx := btcwire.NewMsgTx()
	hash, err := btcwire.NewShaHashFromStr(txid)
	if err != nil {
		return "", err
	}
	outpoint := btcwire.NewOutPoint(hash, uint32(vinIdx))
	ti := btcwire.NewTxIn(outpoint, nil)
	tx.AddTxIn(ti)

	// Construct the tx output
	toAddress, err := btcutil.DecodeAddress(toAddressStr, &btcnet.TestNet3Params)
	if err != nil {
		return "", err
	}
	script, err := btcscript.PayToAddrScript(toAddress)
	if err != nil {
		return "", err
	}
	to := btcwire.NewTxOut(int64(value), script)
	tx.AddTxOut(to)

	// Construct the tx input
	wif, err := btcutil.DecodeWIF(privKeyStr)
	if err != nil {
		return "", err
	}
	privKey := wif.PrivKey
	compressed, err := isCompressed(wif, inputAddressStr)
	if err != nil {
		return "", err
	}
	inputScript, err := hex.DecodeString(inputScriptHex)
	if err != nil {
		return "", err
	}
	sigScript, err := btcscript.SignatureScript(
		tx, 0, inputScript, btcscript.SigHashAll, privKey.ToECDSA(), compressed)
	if err != nil {
		return "", err
	}
	tx.TxIn[0].SignatureScript = sigScript

	// Serialize
	buf := bytes.Buffer{}
	buf.Grow(tx.SerializeSize())
	if err := tx.BtcEncode(&buf, btcwire.ProtocolVersion); err != nil {
		return "", err
	}
	if err := btcchain.CheckTransactionSanity(btcutil.NewTx(tx)); err != nil {
		return "", err
	}

	return hex.EncodeToString(buf.Bytes()), nil
}

func isCompressed(wif *btcutil.WIF, addr string) (bool, error) {
	ser := wif.SerializePubKey()
	if len(ser) != compressedKeySize && len(ser) != uncompressedKeySize {
		return false, fmt.Errorf("unexpected serialized pub key length: %v", len(ser))
	}

	compareAddr, err := btcutil.NewAddressPubKey(ser, &btcnet.TestNet3Params)
	if err != nil {
		return false, err
	}
	compareAddrStr := compareAddr.AddressPubKeyHash().EncodeAddress()

	if addr == compareAddrStr {
		return len(ser) == compressedKeySize, nil
	} else {
		return len(ser) == uncompressedKeySize, nil
	}
}

func genMasterKey() (*hdkeychain.ExtendedKey, error) {
	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	if err != nil {
		return nil, err
	}
	key, err := hdkeychain.NewMaster(seed)
	if err != nil {
		return nil, err
	}
	key.SetNet(&btcnet.TestNet3Params)
	return key, nil
}

func initTempAppDir(t *testing.T) string {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("Init temp dir: %v\n", dir)
	util.SetAppDir(dir)
	return dir
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
