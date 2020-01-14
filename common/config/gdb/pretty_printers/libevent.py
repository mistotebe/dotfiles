#!/usr/bin/env python3

import gdb
import gdb.printing

from pretty_printers.common import CollectionPrinter


EV_FLAGS = {
    "EV_TIMEOUT": 0x01,
    "EV_READ": 0x02,
    "EV_WRITE": 0x04,
    "EV_SIGNAL": 0x08,
    "EV_PERSIST": 0x10,
    "EV_ET": 0x20,
    "EV_FINALIZE": 0x40,
    "EV_CLOSED": 0x80,
}

EV_INTERNAL = {
    "EVLIST_TIMEOUT": 0x01,
    "EVLIST_INSERTED": 0x02,
    "EVLIST_SIGNAL": 0x04,
    "EVLIST_ACTIVE": 0x08,
    "EVLIST_INTERNAL": 0x10,
    "EVLIST_ACTIVE_LATER": 0x20,
    "EVLIST_FINALIZING": 0x40,
}


class EventPrinter:
    """Pretty printer for struct event"""

    def __init__(self, event):
        self.event = event
        self.flags = event['ev_evcallback']['evcb_flags']

    def to_string(self):
        res = []
        for name, flag in EV_INTERNAL.items():
            if self.flags & flag:
                res.append(name)
        if not res:
            return "inactive"
        return "|".join(res)

    def what(self):
        ev = self.event
        flags = 0
        res = []

        # taken from libevent/event.c
        flags |= ev['ev_events'] & (
            EV_FLAGS['EV_READ'] |
            EV_FLAGS['EV_WRITE'] |
            EV_FLAGS['EV_CLOSED'] |
            EV_FLAGS['EV_SIGNAL'] |
            EV_FLAGS['EV_PERSIST'] )

        if self.flags & (EV_INTERNAL['EVLIST_ACTIVE']|EV_INTERNAL['EVLIST_ACTIVE_LATER']):
            flags |= ev['ev_res']
        if self.flags & EV_INTERNAL['EVLIST_TIMEOUT']:
            flags |= EV_FLAGS['EV_TIMEOUT']

        flags &= (
                EV_FLAGS['EV_TIMEOUT'] |
                EV_FLAGS['EV_READ'] |
                EV_FLAGS['EV_WRITE'] |
                EV_FLAGS['EV_CLOSED'] |
                EV_FLAGS['EV_SIGNAL']
        )

        for name, flag in EV_FLAGS.items():
            if flags & flag:
                res.append(name)

        return res or ['nothing']

    def children(self):
        what = self.what()
        res = {
            "base": self.event['ev_base'],
            "what": "|".join(what),
        }

        if 'EV_TIMEOUT' in what:
            #res['activates at'] = abstime(timeradd(self.event['ev_timeout'], self.event['ev_base']['tv_clock_diff']))
            if 'EV_PERSIST' in what:
                res['timeout'] = self.event['ev_io_timeout']

        return res.items()


def register(objfile):
    print("registering libevent printers")
    printer = CollectionPrinter('libevent')

    # pointer printers
    printer.add_pointer_printer('event', r'^event$',
                                EventPrinter)

    if objfile == None:
        objfile = gdb

    gdb.printing.register_pretty_printer(objfile, printer)
