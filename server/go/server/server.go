package main

import (
	"code.google.com/p/go.net/websocket"
	"fmt"
	"net/http"
)

func main() {
	addr := "localhost:4000"
	http.Handle("/", websocket.Handler(handler))
	fmt.Printf("Listening on %v...\n", addr)
	http.ListenAndServe(addr, nil)
}

func handler(ws *websocket.Conn) {
	var in []byte
	if err := websocket.Message.Receive(ws, &in); err != nil {
		return
	}
	fmt.Printf("Got: %v\n", string(in))
}
