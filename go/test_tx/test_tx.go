package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"

	// "github.com/conformal/btcec"
	"github.com/conformal/btcchain"
	"github.com/conformal/btcnet"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
)

func main() {
	// txid := "b45318da30213a18eea15187720701127fd80fc08ec6cb3af680ff3ec942d309"
	// addressStr := "mrpCfWBGDU4bV4enUrFBuw9fp6fKKmikQk"
	// privKeyStr := "cU3pMkjty1b7YRgp5rw2kRoBJzEYESUBrK8zac97yPV3Ev329VKb"
	// inputAddressStr := "ms25MjJtha6UZcRAG2kKLUGkPrNqbXEibb"

	// txid := "9cbad128723a1a24341fb21436fa8a18cc4fad1003cd8228252ea6cc103f0eb6"
	// addressStr := "ms25MjJtha6UZcRAG2kKLUGkPrNqbXEibb"
	// privKeyStr := "cMnPvnwvvzyzVwUvFoCWAkGgXPhNEv783uH1yKie5eShBgVb6RDx"
	// inputAddressStr := "mrpCfWBGDU4bV4enUrFBuw9fp6fKKmikQk"

	txid := "fb3bd02016c6a6ee23397044d7eeb8cf08c1887383cd76fa2c4fa247a42b385e"
	addressStr := "ms25MjJtha6UZcRAG2kKLUGkPrNqbXEibb"
	privKeyStr := "cPceLNEDBNCV7AQn7Dp8hx8ip7BCbU1WrVQzKBGvnKZKgrQVr3cn"
	inputAddressStr := "muL3CwAe68QrZsge2AcyQ1hBPns45x1Rcu"
	vinIdx := 1

	tx := btcwire.NewMsgTx()
	hash, err := btcwire.NewShaHashFromStr(txid)
	if err != nil {
		log.Fatal(err)
	}
	outpoint := btcwire.NewOutPoint(hash, uint32(vinIdx))
	ti := btcwire.NewTxIn(outpoint, nil)
	tx.AddTxIn(ti)

	// Construct the tx output
	address, err := btcutil.DecodeAddress(addressStr, &btcnet.TestNet3Params)
	if err != nil {
		log.Fatal(err)
	}
	script, err := btcscript.PayToAddrScript(address)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("script hex: %v\n", script)
	to := btcwire.NewTxOut(int64(100000), script)
	tx.AddTxOut(to)
	fmt.Printf("tx: %v\n", tx)

	wif, err := btcutil.DecodeWIF(privKeyStr)
	if err != nil {
		log.Fatal(err)
	}
	privKey := wif.PrivKey
	fmt.Printf("key: %v\n", privKey)

	inputAddress, err := btcutil.DecodeAddress(inputAddressStr, &btcnet.TestNet3Params)
	if err != nil {
		log.Fatal(err)
	}
	inputScript, err := btcscript.PayToAddrScript(inputAddress)
	if err != nil {
		log.Fatal(err)
	}
	sigScript, err := btcscript.SignatureScript(
		tx, 0, inputScript, btcscript.SigHashAll, privKey.ToECDSA(), true)
	if err != nil {
		log.Fatal(err)
	}
	tx.TxIn[0].SignatureScript = sigScript
	fmt.Printf("sig script: %v\n", sigScript)

	buf := bytes.Buffer{}
	buf.Grow(tx.SerializeSize())
	if err := tx.BtcEncode(&buf, btcwire.ProtocolVersion); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("btc tx: %v\nhex: %v\n", buf, hex.EncodeToString(buf.Bytes()))

	if err := btcchain.CheckTransactionSanity(btcutil.NewTx(tx)); err != nil {
		log.Fatal(err)
	}
}
