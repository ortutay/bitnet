from electrum import BasePlugin
from electrum.i18n import _

import PyQt4
from PyQt4.QtGui import *
from PyQt4.QtCore import *
import PyQt4.QtCore as QtCore

class Plugin(BasePlugin):
    def fullname(self): return 'Bitnet'

    def description(self): return 'Communication network for Bitcoin wallets'

    def __init__(self, gui, name):
        self.gui = gui
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
        grid.addWidget(QPushButton("Get tokens", w), 0, 0)
        grid.addWidget(QPlainTextEdit("Hello", w), 0, 1)
        return w
