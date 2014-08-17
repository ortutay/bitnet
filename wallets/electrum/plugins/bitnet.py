from electrum import BasePlugin

class Plugin(BasePlugin):
    def fullname(self): return 'Bitnet'

    def description(self): return 'Communication network for Bitcoin wallets'

    def __init__(self, gui, name):
        BasePlugin.__init__(self, gui, name)
        self._is_available = self._init()

    def _init(self):
        return True

    def is_available(self):
        return self._is_available

    def enable(self):
        return BasePlugin.enable(self)
