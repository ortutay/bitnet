package main

import (
	"bitbucket.org/ortutay/bitnet"
	"fmt"
	"github.com/gorilla/rpc/json"
	"net/http"
	"strings"
)

func main() {
	addr := "http://localhost:4000/bitnet"
	args := bitnet.GetTokensArgs{Message: "hello"}
	data, err := json.EncodeClientRequest("Bitnet.GetTokens", args)
	req, err := http.NewRequest("POST", addr, strings.NewReader(string(data)))
	req.Header.Add("Content-Type", "application/json")
	fmt.Printf("args: %v\nreq: %v\nerr: %v\n", args, req, err)

	var client = new(http.Client)
	resp, err := client.Do(req)
	// resp, err := http.Post(addr, "application/json", strings.NewReader(string(req))b)
	fmt.Printf("\nresp: %v\nerr: %v\n", resp, err)
}
