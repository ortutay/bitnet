#!/usr/bin/python

import websocket

if __name__ == "__main__":
  print "hello"
  addr = "localhost:4000"
  ws = websocket.create_connection("ws://" + addr + "/")
  ws.send("hello")
  print "sent"
  ws.close()
