#!/usr/bin/env python3

from .openldap import register
from .lloadd import register
from .posix import register
from .libevent import register

def register():
    openldap.register(None)
    lloadd.register(None)
    posix.register(None)
    libevent.register(None)
