#!/usr/bin/env python3


class RAWConfig:

    SIG = str.encode("EOFEOFEOFEOFEOFX")

    def __init__(self):
        self._chunk = None
        self._identifier = None
        self.BLOCK_SIZE = None
        self._ = None
        self.KEY_SIG = None

    # initializer
    def init(self):
        self._chunk = 65 * 1024
        self._identifier = ".(encrypted)"
        self.BLOCK_SIZE = 16
        self.KEY_SIG = self.SIG
