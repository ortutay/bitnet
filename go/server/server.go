package main

import (
	"bitbucket.org/ortutay/bitnet"
	"log"
	"net"
	"net/http"
	"net/rpc"
)

type BitnetService struct {
	Address bitnet.BitcoinAddress
}

func main() {
	addr := "localhost:4000"
	log.Printf("Listening on %v...\n", addr)

	btcAddr := bitnet.BitcoinAddress("mrvdXP7dNodDu9YcdrFWzfXomnWNvASGnb")
	bitnet := BitnetService{
		Address: btcAddr,
	}
	rpc.Register(&bitnet)
	rpc.HandleHTTP()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	http.Serve(l, nil)
}

func (b *BitnetService) BuyTokens(args *bitnet.BuyTokensArgs, reply *bitnet.BuyTokensReply) error {
	log.Printf("Handling BuyTokens %v\n", args)
	return nil
}
