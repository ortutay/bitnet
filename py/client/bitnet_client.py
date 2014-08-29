#!/usr/bin/python

import base64
import binascii
import datetime
import ecdsa
import hashlib
import json
import logging
import requests
import threading
import time

_JSON_RPC_HEADERS = {"Content-Type": "application/json"}
_DEFAULT_ADDR = "54.187.157.104:8555"

logging.basicConfig(format='%(levelname)s %(name)s %(asctime)-15s %(filename)s:%(lineno)d %(message)s')
_logger = logging.getLogger("bitnet")
# TODO(ortutay): set lower logger level for prod
_logger.setLevel(logging.ERROR)


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

class BitnetRPCException(Exception):
    pass

class BitnetClient:
    def __init__(self, id_priv="", enc_priv="", addr=_DEFAULT_ADDR):
        if not id_priv:
            # TODO(ortutay): generate random
            id_priv="id priv seed"
        self.SetIdPriv(id_priv)

        # TODO(ortutay): handle enc_priv

        self._listeners = {}
        self._next_listener_id = 1
        self._seen_messages = set([])
        self.url = "http://%s/bitnetRPC" % addr
        ClaimTokens(self.url, "", self.PubKeyStr(), "", "claimfree")

    def SetIdPriv(self, id_priv):
        if not isinstance(id_priv, EC_KEY):
            id_priv = EC_KEY(str(id_priv))
        self.id_priv = id_priv
        
    def PubKeyStr(self):
        return self.id_priv.get_public_key()

    def Tokens(self, amount):
        resp = Challenge(self.url)
        challenge = resp["result"]["Challenge"]
        signable = sha256(challenge + str(amount))
        sig = Sign(signable, self.id_priv)
        tokens = {
            "Challenge": challenge,
            "Amount": amount,
            "PubKey": self.PubKeyStr(),
            "Sig": sig,
            }
        return tokens
        
    def Send(self, to_pub_key, message):
        # TODO(ortutay): Cached-pull of recepients privkey, and then encrypt.
        # TODO(ortutay): Default to encryption, and allow plaintext send only
        # with explicit override.
        if not "body" in message:
            dt = datetime.datetime.utcnow().isoformat("T") + "Z"
            message = {
                "type": "bitnet.Plain",
                "datetime": dt,
                "to-pubkey": str(to_pub_key),
                "from-pubkey": self.PubKeyStr(),
                "body": str(message),
            }
        if "encrypted_body" in message:
            raise Exception("Message encryption not yet implemented")

        headers = dict()
        for key in message:
            if key == "body":
                continue
            vals = []
            if isinstance(message[key], basestring):
                vals = [message[key]]
            else:
                for val in message[key]:
                    val += message[key]
            headers[key] = vals
        plaintext_section = {
            "Headers": headers,
            "Body": message["body"],
        }
        message = {
            "Plaintext": plaintext_section,
            "Encrypted": "",
            }
        tokens = self.Tokens(-1)
        # TODO(ortutay): In Python, might be better to "raise" here.
        return StoreMessage(self.url, tokens, message)

    def Listen(self, handler, query=None):
        if not query:
            query = {"to-pubkey": self.PubKeyStr()}
        # Server currently does not charge for "GetMessages" RPC
        tokens = self.Tokens(-1)
        def periodic_poll(client, url, handler, tokens, query):
            while True:
                try:
                    resp = GetMessages(url, tokens, query)
                except BitnetRPCException as e:
                    _logger.error("Error on GetMessages(%s, %s): %s" % (
                        tokens, query, str(e)))
                    continue
                for msg in resp["result"]["Messages"]:
                    h = ""
                    if ("Plaintext" in msg
                        and "Headers" in msg["Plaintext"]
                        and "message-hash" in msg["Plaintext"]["Headers"]):
                        h = msg["Plaintext"]["Headers"]["message-hash"][0]
                    if h:
                        if h in client._seen_messages:
                            continue
                        client._seen_messages.add(h)
                    handler(msg)
                time.sleep(.1)
        id = "get-messages-poll-%d" % self._next_listener_id
        self._next_listener_id += 1
        thr = threading.Thread(
            group=None, target=periodic_poll, name=id,
            args=(self, self.url, handler, tokens, query))
        thr.daemon = True
        thr.start()
        return id

    def StopListening(self, id):
        # TODO(ortutay): implement
        pass

def Challenge(url):
    req = {
        "method": "Bitnet.Challenge",
        "params": [{}],
        "id": 0,
        }
    return _DoRPC(url, req)

def ClaimTokens(url, challenge, pub_key, bitcoin_address, sig):
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
    return _DoRPC(url, req)

def StoreMessage(url, tokens, message):
    req = {
        "method": "Bitnet.StoreMessage",
        "params": [{
            "Tokens": tokens,
            "Message": message,
        }],
        "id": 0,
    }
    return _DoRPC(url, req)

def GetMessages(url, tokens, query):
    req = {
        "method": "Bitnet.GetMessages",
        "params": [{
            "Tokens": tokens,
            "Query": query,
        }],
        "id": 0,
    }
    return _DoRPC(url, req)

def _DoRPC(url, req):
    _logger.info("Sending request to %s: %s", url, str(req))
    resp = requests.post(url, data=json.dumps(req), headers=_JSON_RPC_HEADERS)
    _logger.info("Got response: %s, %s", resp, resp.json())
    resp_json = resp.json()
    if resp_json["error"]:
        raise BitnetRPCException(resp_json["error"])
    return resp_json

def Sign(msg, priv_key):
    sk = ecdsa.SigningKey.from_secret_exponent(
        priv_key.secret,curve=ecdsa.curves.SECP256k1)
    sig = sk.sign_digest(msg, sigencode=ecdsa.util.sigencode_der)
    return base64.b64encode(sig)
        

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
    client = BitnetClient2()
