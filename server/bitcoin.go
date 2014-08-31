package main

import (
	"errors"
	"fmt"
	"github.com/conformal/btcutil"
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
	SetNetwork(net BitcoinNetwork)
	SendRawTransaction(rawTx string) (string, error)
	GetTotalReceived(addr btcutil.Address, minConf uint) (uint64, error)
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
		return "", fmt.Errorf("bitcoin network did not accept transaction: %v", err)
	}
	return data.Transaction.TxHash, nil
}

func (hb *HelloBlock) GetTotalReceived(addr btcutil.Address, minConf uint) (uint64, error) {
	if minConf > 1 {
		// TODO(ortutay): Exact number of confirmations is not specified in their
		// docs, but assume it is 1.
		return 0, errors.New("helloblock.io does not support >1 confirmations")
	}
	data, err := helloblock.GetAddress(addr.EncodeAddress())
	if err != nil {
		return 0, fmt.Errorf("couldn't get address for %v: %v", addr, err)
	}

	if minConf > 0 {
		return data.Address.ConfirmedReceivedValue, nil
	} else {
		return data.Address.TotalReceivedValue, nil
	}
}
