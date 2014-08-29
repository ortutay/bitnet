#!/usr/bin/python
import sys
from bitnet_client import BitnetClient

a = BitnetClient("")
a.Send(sys.argv[1], sys.argv[2])

