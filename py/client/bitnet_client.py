#!/usr/bin/python

import json
import requests

_JSON_RPC_HEADERS = {"Content-Type": "application/json"}

class BitnetClient:
    def __init__(self):
        print "init"
        self._url = "http://localhost:4000/bitnetRPC"

    def BuyTokens(self, raw_tx, pub_key):
        req = {
            "method": "Bitnet.BuyTokens",
            "params": [{"RawTx": raw_tx, "PubKey": pub_key}],
            "id": 0,
            }
        resp = requests.post(
            self._url, data=json.dumps(req), headers=_JSON_RPC_HEADERS)
        print "BuyTokens -> ", resp.json()

if __name__ == "__main__":
    client = BitnetClient()
    client.BuyTokens("rawtx", "pubkey")
