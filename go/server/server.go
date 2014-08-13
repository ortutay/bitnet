package main

import (
	"bitbucket.org/ortutay/bitnet"
	"log"
	"net"
	"net/http"
	"net/rpc"
)

func main() {
	addr := "localhost:4000"
	log.Printf("Listening on %v...\n", addr)

	bitnet := new(BitnetService)
	rpc.Register(bitnet)
	rpc.HandleHTTP()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	http.Serve(l, nil)
}

type BitnetService struct{}

func (b *BitnetService) GetTokens(args *bitnet.GetTokensArgs, reply *bitnet.GetTokensReply) error {
	log.Printf("Handling GetTokens\n")
	reply.Message = "Reply [" + args.Message + "]"
	return nil
}
