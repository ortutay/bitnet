package main

import (
	"bitbucket.org/ortutay/bitnet"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/conformal/btcec"
	"github.com/conformal/btcnet"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/ortutay/helloblock"
	"log"
	"net"
	"net/http"
	"net/rpc"
)

type BitnetService struct {
	Address bitnet.BitcoinAddress
	Datastore *bitnet.Datastore
}

func NewBitnetService(address bitnet.BitcoinAddress) *BitnetService {
	var b BitnetService
	b.Address = address
	b.Datastore = bitnet.NewDatastore() 
	return &b
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
		return errors.New("couldn't decode raw transaction")
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
	log.Printf("Tx value to us: %v -> %v tokens\n", value, numTokens)

	data, err := helloblock.Propagate(args.RawTx)
	if err != nil {
		return errors.New("bitcoin network did not accept transaction")
	}
	log.Printf("Successfully submitted transaction, ID: %v\n", data.Transaction.TxHash)

	pubKeyData, err := hex.DecodeString(args.PubKey)
	if err != nil {
		return errors.New("couldn't decode public key")
	}
	pubKey, err := btcec.ParsePubKey(pubKeyData, btcec.S256())
	if err != nil {
		return errors.New("couldn't decode public key")
	}

	// TODO(ortutay): Getting an error here is bad, because we have already
	// submitted the client's transaction. We should have more handling around
	// this case.
	if err := b.Datastore.AddTokens(pubKey, numTokens); err != nil {
		log.Printf("ERROR: couldn't add tokens in datastore  %v", err)
		return errors.New("Transaction was accepted, but error while crediting tokens. Please report.")
	}

	return nil
}
