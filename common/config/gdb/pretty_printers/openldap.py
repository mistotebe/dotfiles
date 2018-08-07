#!/usr/bin/env python3

import gdb
import gdb.printing

from pretty_printers.common import CollectionPrinter

class LockPrinter:
    """Backup pretty printer for pthread_lock."""

    def __init__(self, lock):
        """Initialize the printer's internal data structures.

        Args:
            value: A gdb.Value representing a struct berval.
        """
        self.lock = lock
        data = lock['__data']
        self.kind = data['__kind']
        self.owner = data['__owner']
        self.locked = data['__lock']

    def display_hint(self):
        return "map"

    def children(self):
        return []

    def to_string(self):
        if self.kind == -1:
            return "Invalid"
        if self.locked:
            if self.kind == 1:
                return "Locked by LWP {self.owner}, depth={self.lock}".format(self=self)
            else:
                return "Locked by LWP {self.owner}".format(self=self)
        return "Unlocked"

class BerValuePrinter:
    """Pretty printer for BerValue."""

    def __init__(self, value):
        """Initialize the printer's internal data structures.

        Args:
            value: A gdb.Value representing a struct berval.
        """
        self.val = value['bv_val']
        self.len = value['bv_len']
        self.string_like = True
        try:
            if self.len and self.val:
                s = self.val.string(length=self.len)
                if self.len != len(s):
                    self.string_like = False
                else:
                    self.val = s
        except (UnicodeDecodeError, OverflowError):
            self.string_like = False

    def display_hint(self):
        """type is string unless it's BVNULL

        that's then when we need special treatment of to_string"""
        if not self.len and not self.val:
            return "map"
        return "string"

    def children(self):
        if self.val and not self.string_like:
            return {
                    'bv_len': self.len,
                    'bv_val': self.val,
            }.items()
        else:
            # string or BVNULL
            return []

    def to_string(self):
        """gdb API function.

        This is called from gdb when we try to print a struct berval.
        """
        if self.string_like:
            if self.len:
                return self.val
            if self.val:
                return ""
            # Otherwise, we say it's a map but don't return any children
            # If we said it's a string, gdb would escape it and put quotes around
            return 'BVNULL'

class SockAddrPrinter:
    def __init__(self, value):
        self.value = value
        self.family = value['sa_addr']['sa_family']
        if self.family == socket.AF_UNIX:
            self.member = 'sa_un_addr'
        elif self.family == socket.AF_INET:
            self.member = 'sa_in_addr'
        elif self.family == socket.AF_INET6:
            self.member = 'sa_in6_addr'
        else:
            self.member = 'sa_addr'

    def to_string(self):
        return self.value[self.member]

class AttrDescPrinter:
    """Pretty printer for AttributeDescription"""

    def __init__(self, value):
        self.ad = value
        self.name = value['ad_cname']

    def to_string(self):
        return self.name

class OCPrinter:
    """Pretty printer for ObjectClass"""

    def __init__(self, oc):
        self.oc = oc

    def to_string(self):
        return self.oc['soc_cname']

class EntryPrinter:
    """Pretty printer for Entry"""

    def __init__(self, e):
        self.e = e

    def to_string(self):
        return self.e['e_name']

    def children(self):
        return {
        #    "dn": self.e['e_name'],
        }.items()

def finish_printer(printer):
    mutex = gdb.lookup_type('pthread_mutex_t')

def register(objfile):
    print("registering OpenLDAP printers")
    printer = CollectionPrinter('OpenLDAP')

    printer.add_printer('BerValue', r'^berval$',
                        BerValuePrinter)
    printer.add_printer('mutex', r'^ldap_pvt_thread_mutex_t$',
                        LockPrinter)
    printer.add_printer('Sockaddr', r'^Sockaddr$', SockAddrPrinter)

    # pointer printers
    printer.add_pointer_printer('AttributeDescription',
                                r'^AttributeDescription$',
                                AttrDescPrinter)
    printer.add_pointer_printer('ObjectClass', r'^ObjectClass$',
                                OCPrinter)
    printer.add_pointer_printer('Entry', r'^Entry$',
                                EntryPrinter)

    # register pthread aliases if possible
    gdb.post_event(finish_printer)

    if objfile == None:
        objfile = gdb

    gdb.printing.register_pretty_printer(objfile, printer)
