package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
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
)

var (
	compressedKeySize   = 33
	uncompressedKeySize = 65
)

// TODO(ortutay): Move this into github.com/ortutay/helloblock
type HelloBlockUnspent struct {
	TxHash       string `json:"txHash"`
	Index        int    `json:"index"`
	ScriptPubKey string `json:"scriptPubKey"`
	Value        int    `json:"value"`
	Address      string `json:"address"`
}

type HelloBlockFaucetData struct {
	PrivateKeyWIF string              `json:"privateKeyWIF"`
	PrivateKeyHex string              `json:"privateKeyHex"`
	Address       string              `json:"address"`
	Hash160       string              `json:"hash160"`
	FaucetType    int                 `json:"faucetType"`
	Unspents      []HelloBlockUnspent `json:"unspents"`
}

type HelloBlockFaucetReply struct {
	Status string               `json:"status"`
	Data   HelloBlockFaucetData `json:"data"`
}

func TestBuyTokens(t *testing.T) {
	btcAddr := "ms25MjJtha6UZcRAG2kKLUGkPrNqbXEibb"
	service := NewBitnetService(bitnet.BitcoinAddress(btcAddr))
	// defer os.RemoveAll(initTempAppDir(t))
	_ = os.RemoveAll
	initTempAppDir(t)

	rawTx, err := genTestRawTx(btcAddr)
	if err != nil {
		t.Fatal(err)
	}

	key, err := genMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	ecPubKey, err := key.ECPubKey()
	if err != nil {
		t.Fatal(err)
	}
	buf := ecPubKey.SerializeCompressed()
	hexPubKey := hex.EncodeToString(buf)

	args := bitnet.BuyTokensArgs{
		RawTx:  rawTx,
		PubKey: hexPubKey,
	}

	fmt.Printf("raw tx: %v\nkey: %v\nargs: %v\n", rawTx, key, args)
	var reply bitnet.BuyTokensReply
	if err := service.BuyTokens(&args, &reply); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("reply: %v\n", reply)
}

func genTestRawTx(toAddressStr string) (string, error) {
	// Get testnet privkey from helloblock.io
	resp, err := http.Get("https://testnet.helloblock.io/v1/faucet?type=1")
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var reply HelloBlockFaucetReply
	if err := json.Unmarshal(body, &reply); err != nil {
		return "", err
	}
	fmt.Printf("helloblock.io faucet: %v\n", string(body))
	if reply.Status != "success" {
		return "", fmt.Errorf("failed call to helloblock %v", reply)
	}

	// Collect tx variables
	txid := reply.Data.Unspents[0].TxHash
	privKeyStr := reply.Data.PrivateKeyWIF
	inputAddressStr := reply.Data.Unspents[0].Address
	inputScriptHex := reply.Data.Unspents[0].ScriptPubKey
	vinIdx := reply.Data.Unspents[0].Index
	fee := 1000
	value := reply.Data.Unspents[0].Value - fee

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
