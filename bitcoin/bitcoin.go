package bitcoin

import (
	"errors"
	log "github.com/golang/glog"
	"github.com/ortutay/helloblock"
)

// This file contains tools for interacting with the bitcoin network. Currently,
// the implementation relies on helloblock.io API, but we can later add one that
// interacts with a local bitcoind/btcd instance.

type BitcoinNetwork string

const (
	Testnet3 BitcoinNetwork = "testnet3"
	Mainnet                 = "mainnet"
)

type Bitcoin interface {
	SetNetwork(BitcoinNetwork)
	SendRawTransaction(string) (string, error)
}

type HelloBlock struct {
}

func (hb *HelloBlock) SetNetwork(net BitcoinNetwork) {
	switch net {
	case Testnet3:
		helloblock.SetNetwork(helloblock.Testnet)
	case Mainnet:
		helloblock.SetNetwork(helloblock.Mainnet)
	default:
		log.Fatalf("unexpected network: %v", net)
	}
}

func (hb *HelloBlock) SendRawTransaction(rawTx string) (string, error) {
	data, err := helloblock.Propagate(rawTx)
	if err != nil {
		return "", errors.New("bitcoin network did not accept transaction")
	}
	return data.Transaction.TxHash, nil
}
