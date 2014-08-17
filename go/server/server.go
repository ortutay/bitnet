package main

import (
	"errors"
	"encoding/hex"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcnet"
	"github.com/conformal/btcscript"
	"github.com/ortutay/helloblock"
	"bitbucket.org/ortutay/bitnet"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"fmt"
)

type BitnetService struct {
	Address bitnet.BitcoinAddress
}

func main() {
	addr := "localhost:4000"
	log.Printf("Listening on %v...\n", addr)

	helloblock.SetNetwork(helloblock.Testnet)
	btcAddr := bitnet.BitcoinAddress("mrvdXP7dNodDu9YcdrFWzfXomnWNvASGnb")
	bitnet := BitnetService{Address: btcAddr}
	rpc.Register(&bitnet)
	rpc.HandleHTTP()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	http.Serve(l, nil)
}

func (b *BitnetService) netParams() *btcnet.Params {
	return &btcnet.TestNet3Params
}

func (b *BitnetService) BuyTokens(args *bitnet.BuyTokensArgs, reply *bitnet.BuyTokensReply) error {
	log.Printf("Handling BuyTokens %v\n", args)
	txData, err := hex.DecodeString(args.RawTx)
	if err != nil {
		return fmt.Errorf("couldn't decoe hex: %v", err)
	}
	tx, err := btcutil.NewTxFromBytes(txData)
	if err != nil {
		return fmt.Errorf("couldn't decode tx: %v", err)
	}
	log.Printf("got tx: %v\n", tx)
	value := int64(0)
	for _, out := range tx.MsgTx().TxOut {
		scriptClass, addresses, _, err := btcscript.ExtractPkScriptAddrs(
			out.PkScript, b.netParams())
		if err != nil {
			log.Printf("ERROR: couldn't decode %v: %v", out.PkScript, err)
			return errors.New("couldn't decode transaction")
		}
		if scriptClass != btcscript.PubKeyHashTy {
			continue
		}
		fmt.Printf("class: %v, addrs: %v\n", scriptClass, addresses)
		if addresses[0].String() != b.Address.String() {
			continue
		}
		value += out.Value
	}
	numTokens := value * bitnet.TokensPerSatoshi
	log.Printf("tx value to us: %v -> %v tokens\n", value, numTokens)
	return nil
}
