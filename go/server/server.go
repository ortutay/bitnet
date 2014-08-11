package main

import (
	"bitbucket.org/ortutay/bitnet"
	// "github.com/gorilla/rpc"
	// "github.com/gorilla/rpc/json"
	"log"
	"net"
	"net/http"
	"net/rpc"
	// "net/rpc/jsonrpc"
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

	// s := rpc.NewServer()
	// // s.RegisterCodec(json.NewCodec(), "application/json")
	// s.RegisterCodec(jsonrpc.NewClientCodec(), "application/json")
	// s.RegisterService(new(BitnetService), "Bitnet")

	// http.Handle("/bitnet", s)
	// http.ListenAndServe(addr, nil)
}

type BitnetService struct{}

func (b *BitnetService) GetTokens(args *bitnet.GetTokensArgs, reply *bitnet.GetTokensReply) error {
	log.Printf("Handling GetTokens\n")
	reply.Message = "Reply [" + args.Message + "]"
	return nil
}
