#!/usr/bin/env python3

from . import openldap
from . import lloadd
from . import posix
from . import libevent


def register():
    openldap.register(None)
    lloadd.register(None)
    posix.register(None)
    libevent.register(None)
