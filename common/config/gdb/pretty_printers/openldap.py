#!/usr/bin/env python3

import gdb
import gdb.printing

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
            elif self.val:
                return "zero len string"
            else:
                # in this case, we say it's a map but don't return any children
                # if we said it's a string, gdb would escape it and put quotes around
                return 'BVNULL'

def finish_printer(printer):
    mutex = gdb.lookup_type('pthread_mutex_t')

def register(objfile):
    print("registering OpenLDAP printers")
    printer = gdb.printing.RegexpCollectionPrettyPrinter('OpenLDAP')

    printer.add_printer('BerValue', r'^berval$',
                        BerValuePrinter)
    printer.add_printer('mutex', r'^ldap_pvt_thread_mutex_t$',
                        LockPrinter)
    # register pthread aliases if possible
    gdb.post_event(finish_printer)

    if objfile == None:
        objfile = gdb

    gdb.printing.register_pretty_printer(objfile, printer)
