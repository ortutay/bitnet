#!/usr/bin/python

import json
import requests
import logging

_JSON_RPC_HEADERS = {"Content-Type": "application/json"}

# Stub Plugin, for when we are loading from Electrum wallet. No-op otherwise.
try:
    from electrum import BasePlugin
    class Plugin(BasePlugin):
        def fullname(self): return ''
        def description(self): return ''
        def is_available(self): return False
        def enable(self): return False
except:
    pass

class BitnetClient:
    def __init__(self):
        logging.basicConfig(format='%(levelname)s %(name)s %(asctime)-15s %(filename)s:%(lineno)d %(message)s')
        self._logger = logging.getLogger("bitnet")
        self._url = "http://localhost:4000/bitnetRPC"
        # TODO(ortutay): set lower logger level for prod
        self._logger.setLevel(logging.DEBUG)

    def BuyTokens(self, raw_tx, pub_key):
        req = {
            "method": "Bitnet.BuyTokens",
            "params": [{"RawTx": raw_tx, "PubKey": pub_key}],
            "id": 0,
            }
        self._logger.info("sending request to %s: %s", self._url, str(req))
        resp = requests.post(
            self._url, data=json.dumps(req), headers=_JSON_RPC_HEADERS)
        return resp.json()

if __name__ == "__main__":
    client = BitnetClient()
    client.BuyTokens("rawtx", "pubkey")
