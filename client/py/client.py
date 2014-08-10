#!/usr/bin/python

import websocket

if __name__ == "__main__":
  addr = "localhost:4000"
  ws = websocket.create_connection("ws://" + addr + "/")
  ws.send("hello")
  ws.close()
