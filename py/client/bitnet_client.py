#!/usr/bin/python

import base64
import hashlib
import ecdsa
import binascii
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
        self._logger.info("Sending request to %s: %s", self._url, str(req))
        resp = requests.post(
            self._url, data=json.dumps(req), headers=_JSON_RPC_HEADERS)
        self._logger.info("Got response: %s", resp)
        return resp.json()

    def Challenge(self):
        req = {
            "method": "Bitnet.Challenge",
            "params": [{}],
            "id": 0,
            }
        self._logger.info("Sending request to %s: %s", self._url, str(req))
        resp = requests.post(
            self._url, data=json.dumps(req), headers=_JSON_RPC_HEADERS)
        self._logger.info("Got response: %s", resp)
        return resp.json()

    def ClaimTokens(self, challenge, pub_key, bitcoin_address, sig):
        req = {
            "method": "Bitnet.ClaimTokens",
            "params": [{
                "Challenge": challenge,
                "PubKey": pub_key,
                "BitcoinAddress": bitcoin_address,
                "Sig": sig,
            }],
            "id": 0,
        }
        self._logger.info("Sending request to %s: %s", self._url, str(req))
        resp = requests.post(
            self._url, data=json.dumps(req), headers=_JSON_RPC_HEADERS)
        self._logger.info("Got response: %s", resp)
        return resp.json()

    # Args:
    #   priv_key: EC_KEY
    def GetBalance(self, priv_key):
        challenge_resp = self.Challenge()
        if challenge_resp["error"]:
            return {"error": challenge_resp["error"]}
        pub_key_str = priv_key.get_public_key()
        challenge = challenge_resp['result']['Challenge']
        msg = challenge + pub_key_str
        msg_hash = sha256(msg)
        msg_hash_hex = binascii.hexlify(msg_hash)
        sk = ecdsa.SigningKey.from_secret_exponent(
            priv_key.secret,curve=ecdsa.curves.SECP256k1)
        to_sign = msg_hash_hex[:32]
        sig = sk.sign_digest(to_sign, sigencode=ecdsa.util.sigencode_der)
        sig_enc = base64.b64encode(sig)
        req = {
            "method": "Bitnet.GetBalance",
            "params": [{
                "Challenge": challenge,
                "PubKey": pub_key_str,
                "Sig": sig_enc,
            }],
            "id": 0,
        }
        self._logger.info("Sending request to %s: %s", self._url, str(req))
        resp = requests.post(
            self._url, data=json.dumps(req), headers=_JSON_RPC_HEADERS)
        self._logger.info("Got response: %s", resp.json())
        return resp.json()


# From electrum.bitcoin
class EC_KEY(object):
    def __init__(self, k):
        secret = ecdsa.util.string_to_number(k)
        self.pubkey = ecdsa.ecdsa.Public_key( ecdsa.ecdsa.generator_secp256k1, ecdsa.ecdsa.generator_secp256k1 * secret )
        self.privkey = ecdsa.ecdsa.Private_key( self.pubkey, secret )
        self.secret = secret

    def get_public_key(self, compressed=True):
        return point_to_ser(self.pubkey.point, compressed).encode('hex')

def point_to_ser(P, comp=True):
    if comp:
        return ( ('%02x'%(2+(P.y()&1)))+('%064x'%P.x()) ).decode('hex')
    return ( '04'+('%064x'%P.x())+('%064x'%P.y()) ).decode('hex')

def sha256(x):
    return hashlib.sha256(x).digest()

if __name__ == "__main__":
    client = BitnetClient()
    client.BuyTokens("rawtx", "pubkey")
