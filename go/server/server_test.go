package main

import (
	"bytes"
	"io/ioutil"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/conformal/btcec"
	"github.com/conformal/btcwire"
	"github.com/conformal/btcnet"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcscript"
)

type HelloBlockUnspent struct {
	TxHash string `json:"txHash"`
	Index int `json:"index"`
	ScriptPubKey string `json:"scriptPubKey"`
	Value int `json:"value"`
}

type HelloBlockFaucetData struct {
	PrivateKeyWIF string `json:"privateKeyWIF"`
	PrivateKeyHex string `json:"privateKeyHex"`
	Address string `json:"address"`
	Hash160 string `json:"hash160"`
	FaucetType int `json:"faucetType"`
	Unspents []HelloBlockUnspent `json:"unspents"`
}

type HelloBlockFaucetReply struct {
	Status string `json:"status"`
	Data HelloBlockFaucetData `json:"data"`
}

func TestBuyTokens(t *testing.T) {
	// get testnet coins from helloblock.io
	//   construct tx in
	//   construct tx out
	//   construct tx
	// sign tx

	resp, err := http.Get("https://testnet.helloblock.io/v1/faucet?type=1")
	if err != nil {
		t.Fatal(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var reply HelloBlockFaucetReply
	if err := json.Unmarshal(body, &reply); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("body: %v\nresp: %v\n", string(body), reply)


	// Construct tx
	tx := btcwire.NewMsgTx()
	// Construct the tx input
	privKeyHex := reply.Data.PrivateKeyHex
	utxo := reply.Data.Unspents[0]
	hash, err := btcwire.NewShaHashFromStr(utxo.TxHash)
	if err != nil {
		t.Fatal(err)
	}
	outpoint := btcwire.NewOutPoint(hash, uint32(utxo.Index))
	ti := btcwire.NewTxIn(outpoint, nil)
	tx.AddTxIn(ti)

	// Construct the tx output
	addressStr := "mrvdXP7dNodDu9YcdrFWzfXomnWNvASGnb"
	address, err := btcutil.DecodeAddress(addressStr, &btcnet.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}
	script, err := btcscript.PayToAddrScript(address)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("script hex: %v\n", script)
	to := btcwire.NewTxOut(int64(100000-1000), script)
	tx.AddTxOut(to)

	fmt.Printf("tx: %v\n", tx)

	curve := btcec.S256()
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	privKey, _ := btcec.PrivKeyFromBytes(curve, privKeyBytes)
	fmt.Printf("key: %v\n", privKey)
	sigScript, err := btcscript.SignatureScript(
		tx, 0, to.PkScript, btcscript.SigHashAll, privKey.ToECDSA(), false)
	if err != nil {
		t.Fatal(err)
	}
	ti.SignatureScript = sigScript
	fmt.Printf("sig script: %v\n", sigScript)

	buf := bytes.Buffer{}
	buf.Grow(tx.SerializeSize())
	if err := tx.BtcEncode(&buf, btcwire.ProtocolVersion); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("btc tx: %v\nhex: %v\n", buf, hex.EncodeToString(buf.Bytes()))
}
