package main

import (
	"github.com/ortutay/bitnet"
	"fmt"
	"github.com/gorilla/rpc/json"
	"net/http"
	"strings"
)

func main() {
	addr := "http://localhost:4000/bitnet"
	args := bitnet.BuyTokensArgs{RawTx: "x", Pub: "x"}
	data, err := json.EncodeClientRequest("Bitnet.BuyTokens", args)
	req, err := http.NewRequest("POST", addr, strings.NewReader(string(data)))
	req.Header.Add("Content-Type", "application/json")
	fmt.Printf("args: %v\nreq: %v\nerr: %v\n", args, req, err)

	var client = new(http.Client)
	resp, err := client.Do(req)
	// resp, err := http.Post(addr, "application/json", strings.NewReader(string(req))b)
	fmt.Printf("\nresp: %v\nerr: %v\n", resp, err)
}
