import binascii
import ecdsa
from electrum import BasePlugin
from electrum.i18n import _
from electrum.account import *

import bitnet_client

import PyQt4
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

class Plugin(BasePlugin):
    def fullname(self): return 'Bitnet'

    def description(self): return 'Communication network for Bitcoin wallets'

    def __init__(self, gui, name):
        self.gui = gui
        # TODO(ortutay): real priv key
        self.priv_key_x = ecdsa.SigningKey.from_secret_exponent(100, curve=ecdsa.curves.SECP256k1)
        self.priv_key = bitnet_client.EC_KEY("00")
        self.client = bitnet_client.BitnetClient()
        BasePlugin.__init__(self, gui, name)
        self._is_available = self._init()

    def _init(self):
        return True

    def is_available(self):
        return self._is_available

    def enable(self):
        return BasePlugin.enable(self)

    def init(self):
        self.gui.main_window.tabs.addTab(self.create_bitnet_tab(), _('Bitnet'))
    
    def create_bitnet_tab(self):
        w = QWidget()
        self.bitnet_grid = grid = QGridLayout(w)
        grid.setSpacing(8)
        
        b = QPushButton("Get tokens", w)
        b.clicked.connect(lambda: self.do_get_tokens())
        grid.addWidget(b, 0, 0)

        b = QPushButton("Claim tokens", w)
        b.clicked.connect(lambda: self.do_claim_tokens())
        grid.addWidget(b, 1, 0)

        self.dialog = dialog = QPlainTextEdit("", w)
        grid.addWidget(dialog, 2, 1)
        return w

    def do_get_tokens(self):
        resp = self.client.BuyTokens("<<rawtx>>", "<<pubkey>>")
        self.dialog.appendPlainText("server says: " + str(resp))

    def do_claim_tokens(self):
        pub_key_str = self.priv_key.get_public_key()
        resp = self.client.ClaimTokens("", pub_key_str, "", "claimfree")
        self.dialog.appendPlainText("server says: " + str(resp))
        
        resp = self.client.GetBalance(self.priv_key)
        self.dialog.appendPlainText("server says: " + str(resp))

