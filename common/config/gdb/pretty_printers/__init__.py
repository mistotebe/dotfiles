#!/usr/bin/env python3

from .openldap import register
from .posix import register
from .libevent import register

def register():
    openldap.register(None)
    posix.register(None)
    libevent.register(None)
