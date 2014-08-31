package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/ortutay/bitnet"
	"github.com/ortutay/bitnet/util"

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
	defer os.RemoveAll(util.InitTempAppDir(t))
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
	if err != nil {
		t.Fatal(err)
	}

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
	defer os.RemoveAll(util.InitTempAppDir(t))
	service := NewBitnetServiceOnHelloBlock(bitnet.BitcoinAddress(btcAddr))

	// 1) Get challenge string
	var challengeReply bitnet.ChallengeReply
	if err := service.Challenge(nil, &bitnet.ChallengeArgs{}, &challengeReply); err != nil {
		t.Fatal(err)
	}

	// 2) Claim the tokens by signing with an address holding BTC
	btcPrivKeyStr := testnetWIF
	inputAddressStr := testnetAdddress
	wif, err := btcutil.DecodeWIF(btcPrivKeyStr)
	if err != nil {
		t.Fatal(err)
	}
	btcPrivKey := wif.PrivKey

	// Tokens destination
	master, err := genMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	pubKeyHex, err := pubKeyAsHex(master)
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
	btcSig, err := bitnet.GetSigBitcoin(
		&claimArgs, btcPrivKey, inputAddressStr, &btcnet.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}
	claimArgs.Sig = btcSig

	var claimReply bitnet.ClaimTokensReply

	if err := service.ClaimTokens(nil, &claimArgs, &claimReply); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("claim reply: %v\n", claimReply)

	// 3) Get new challange and check balance
	balanceReply, err := getBalance(service, master, pubKeyHex)
	if err != nil {
		t.Fatal(err)
	}

	if balanceReply.Balance != bitnet.TokensForAddressWithBalance {
		t.Errorf("Did not get expected balance\nwant: %v\ngot:  %v\n",
			bitnet.TokensForAddressWithBalance, balanceReply.Balance)
	}
}

func TestBurn(t *testing.T) {
	defer os.RemoveAll(util.InitTempAppDir(t))

	service := NewBitnetServiceOnHelloBlock(bitnet.BitcoinAddress(btcAddr))
	master, err := genMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := master.ECPubKey()
	if err != nil {
		t.Fatal(err)
	}
	pubKeyHex, err := pubKeyAsHex(master)
	if err != nil {
		t.Fatal(err)
	}

	// Grant tokens
	if err := service.Datastore.AddTokens(pubKey, 1000); err != nil {
		t.Fatal(err)
	}

	// Get challenge string
	var challengeReply bitnet.ChallengeReply
	if err := service.Challenge(nil, &bitnet.ChallengeArgs{}, &challengeReply); err != nil {
		t.Fatal(err)
	}

	// Burn tokens
	burnArgs := bitnet.BurnArgs{
		Tokens: bitnet.TokenTransaction{
			Challenge: challengeReply.Challenge,
			Amount:    100,
			PubKey:    pubKeyHex,
		},
	}
	privKey, err := master.ECPrivKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := bitnet.GetSig(&burnArgs.Tokens, privKey)
	if err != nil {
		t.Fatal(err)
	}
	burnArgs.Tokens.Sig = sig
	var burnReply bitnet.BurnReply
	if err := service.Burn(nil, &burnArgs, &burnReply); err != nil {
		t.Fatal(err)
	}

	// 3) Verify balance
	balanceReply, err := getBalance(service, master, pubKeyHex)
	if err != nil {
		t.Fatal(err)
	}

	if balanceReply.Balance != 900 {
		t.Errorf("Did not get expected balance\nwant: %v\ngot:  %v\n",
			900, balanceReply.Balance)
	}
}

func TestStoreAndGetMessage(t *testing.T) {
	defer os.RemoveAll(util.InitTempAppDir(t))

	service := NewBitnetServiceOnHelloBlock(bitnet.BitcoinAddress(btcAddr))
	master, err := genMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := master.ECPrivKey()
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := master.ECPubKey()
	if err != nil {
		t.Fatal(err)
	}
	pubKeyHex, err := pubKeyAsHex(master)
	if err != nil {
		t.Fatal(err)
	}

	// Grant tokens
	if err := service.Datastore.AddTokens(pubKey, 100000); err != nil {
		t.Fatal(err)
	}

	// Get challenge string
	var challengeReply bitnet.ChallengeReply
	if err := service.Challenge(nil, &bitnet.ChallengeArgs{}, &challengeReply); err != nil {
		t.Fatal(err)
	}

	// Store the message
	msg := bitnet.Message{
		Plaintext: bitnet.Section{Body: "some message content"},
		Encrypted: "aDkje840klD/ad",
	}
	msg.Plaintext.AddHeader("datetime", "1985-04-12T23:20:50.52Z")
	msg.Plaintext.AddHeader("from-pubkey", pubKeyHex)
	msg.Plaintext.AddHeader("type", "coinjoin")
	msg.Plaintext.AddHeader("-coinjoin-header", "additional data")
	sig, err := bitnet.GetSig(&msg, privKey)
	if err != nil {
		t.Fatal(err)
	}
	msg.Plaintext.AddHeader("from-sig", sig)
	storeArgs := bitnet.StoreMessageArgs{
		Tokens: bitnet.TokenTransaction{
			Challenge: challengeReply.Challenge,
			Amount:    100,
			PubKey:    pubKeyHex,
		},
		Message: msg,
	}
	tokensSig, err := bitnet.GetSig(&storeArgs.Tokens, privKey)
	if err != nil {
		t.Fatal(err)
	}
	storeArgs.Tokens.Sig = tokensSig

	if err := service.StoreMessage(nil, &storeArgs, &bitnet.StoreMessageReply{}); err != nil {
		t.Fatal(err)
	}

	// Get the message
	getArgs := bitnet.GetMessagesArgs{
		Query: bitnet.Query{
			Headers: map[string]string{"sender-pubkey =": pubKeyHex},
		},
	}
	var getReply bitnet.GetMessagesReply
	if err := service.GetMessages(nil, &getArgs, &getReply); err != nil {
		t.Fatal(err)
	}
	if len(getReply.Messages) != 1 {
		t.Fatalf("expected to get 1 message, got %d", len(getReply.Messages))
	}
	if getReply.Messages[0].HashHex() != msg.HashHex() {
		t.Fatalf("messages do not match:\nwant: %v\n got: %v", msg, getReply.Messages[0])
	}
}

func getBalance(service *BitnetService, master *hdkeychain.ExtendedKey, pubKeyHex string) (*bitnet.GetBalanceReply, error) {
	var challengeReply bitnet.ChallengeReply
	if err := service.Challenge(nil, &bitnet.ChallengeArgs{}, &challengeReply); err != nil {
		return nil, err
	}
	balanceArgs := bitnet.GetBalanceArgs{
		Challenge: challengeReply.Challenge,
		PubKey:    pubKeyHex,
	}
	privKey, err := master.ECPrivKey()
	if err != nil {
		return nil, err
	}
	sig, err := bitnet.GetSig(&balanceArgs, privKey)
	if err != nil {
		return nil, err
	}
	balanceArgs.Sig = sig
	fmt.Printf("get balance args: %v\n", balanceArgs)
	var balanceReply bitnet.GetBalanceReply
	if err := service.GetBalance(nil, &balanceArgs, &balanceReply); err != nil {
		return nil, err
	}
	fmt.Printf("balance reply: %v\n", balanceReply)
	return &balanceReply, nil
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

func pubKeyAsHex(key *hdkeychain.ExtendedKey) (string, error) {
	pubKey, err := key.ECPubKey()
	if err != nil {
		return "", err
	}
	buf := pubKey.SerializeCompressed()
	pubKeyHex := hex.EncodeToString(buf)
	return pubKeyHex, nil
}
