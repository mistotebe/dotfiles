#!/usr/bin/env python3

from . import openldap
from . import lloadd


def register():
    openldap.register(None)
    lloadd.register(None)
