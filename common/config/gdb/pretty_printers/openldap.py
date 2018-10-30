#!/usr/bin/env python3

import gdb
import gdb.printing

import socket

from pretty_printers.common import CollectionPrinter, AnnotatedStructPrinter

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
                return "Locked by LWP {self.owner}, depth={self.locked}".format(self=self)
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

class TaskPrinter:
    """Pretty printer for ldap_int_thread_task_s"""

    def __init__(self, work):
        self.work = work

    def to_string(self):
        return self.work['ltt_start_routine']

    def children(self):
        return {
            "arg": self.work['ltt_arg'],
        }.items()

class QueuePrinter:
    """Pretty printer for ldap_int_thread_poolq_s"""

    def __init__(self, queue):
        self.queue = queue

    def to_string(self):
        return None

    def children(self):
        return {
            "mutex": self.queue['ltp_mutex'],
            #"cond": self.queue['ltp_cond'],
            "work": self.queue['ltp_work_list']['stqh_first']
        }.items()

class PoolPrinter:
    """Pretty printer for ldap_pvt_thread_pool_t"""

    def __init__(self, pool):
        self.pool = pool

    def to_string(self):
        state = self.pool['ltp_pause']
        state_string = ""
        if state:
            state_string = "paused" if state == 2 else "pausing"

        return "{}".format(state_string)

    def children(self):
        return {
            "mutex": self.pool['ltp_mutex'],
            #"cond": self.pool['ltp_cond'],
            "queues": self.pool['ltp_numqs'],
            "queue": self.pool['ltp_wqs'][0],
        }.items()

class DBPrinter(AnnotatedStructPrinter):
    """Pretty printer for BackendDB"""
    include = ['be_rootdn', 'be_next']

    flags = {
        'NOLASTMOD': 0x0001,
        'NO_SCHEMA_CHECK': 0x0002,
        'HIDDEN': 0x0004,
        'ONE_SUFFIX': 0x0008,
        'GLUE_INSTANCE': 0x0010,
        'GLUE_SUBORDINATE': 0x0020,
        'GLUE_LINKED': 0x0040,
        'GLUE_ADVERTISE': 0x0080,
        'OVERLAY': 0x0100,
        'GLOBAL_OVERLAY': 0x0200,
        'DYNAMIC': 0x0400,
        'MONITORING': 0x0800,
        'SHADOW': 0x8000,
        'SINGLE_SHADOW': 0x4000,
        'SYNC_SHADOW': 0x1000,
        'SLURP_SHADOW': 0x2000,
        'CLEAN': 0x10000,
        'ACL_ADD': 0x20000,
        'SYNC_SUBENTRY': 0x40000,
        'MULTI_SHADOW': 0x80000,
        'DISABLED': 0x100000,
    }

    def to_string(self):
        if not self.value['bd_self']:
            return "fake DB"
        return self.value['be_suffix'][0]

    def children(self):
        if not self.value['bd_self']:
            return []

        result = self.children_dict(self.include)

        result['type'] = self.value['bd_info']['bi_type']
        result.move_to_end('type', last=False)

        result['be_next'] = gdb.default_visualizer(result['be_next']['stqe_next']).to_string()

        flags = self.value['be_flags']
        if flags:
            result['flags'] = []
            for flag, value in self.flags.items():
                if flags & value:
                    result['flags'].append(flag)
                    flags &= ~value
            if flags:
                result['flags'].append(str(flags))
            result['flags'] = '|'.join(result['flags'])

        return result.items()

class OperationPrinter(AnnotatedStructPrinter):
    """Pretty printer for Operation"""
    exclude = ['o_next']
    exclude_false = [
        'o_abandon', 'o_cancel', 'o_groups', 'o_do_not_cache',
        'o_is_auth_check', 'o_dont_replicate', 'o_nocaching',
        'o_delete_glue_parent', 'o_no_schema_check', 'o_no_subordinate_glue',
        'o_controls', 'o_ber', 'o_res_ber', 'o_ctrls', 'o_private',
    ]

    members = {
        0x42: ["Unbind request", None],
        0x4a: ["Delete request", None],
        0x50: ["Abandon request", 'oq_abandon'],
        0x60: ["Bind request", 'oq_bind'],
        0x63: ["Search request", 'oq_search'],
        0x66: ["Modify request", 'oq_modify'],
        0x68: ["Add request", 'oq_add'],
        0x6c: ["ModRDN request", 'oq_modrdn'],
        0x6e: ["Compare request", 'oq_compare'],
        0x77: ["Extended request", ''],
    }

    def to_string(self):
        tag = int(self.value['o_tag'])
        return self.members.get(tag, ['Unknown request: 0x{:x}'.format(tag)])[0]

    def children(self):
        result = self.children_dict()
        tag = int(result.pop('o_tag'))

        member = self.members.get(tag, ['', ''])[1]
        if member is not None:
            request = result['o_request']
            if member:
                result['o_request'] = request[member]
        else:
            del result['o_request']

        return result.items()

def finish_printer(printer):
    #mutex = gdb.lookup_type('pthread_mutex_t')

    condition = gdb.lookup_type('pthread_cond_t')
    printer.add_printer('condition', r'^ldap_pvt_thread_cond_t$',
                        gdb.default_visualizer(condition))

def register(objfile):
    print("registering OpenLDAP printers")
    printer = CollectionPrinter('OpenLDAP')

    printer.add_printer('BerValue', r'^berval$',
                        BerValuePrinter)
    printer.add_printer('mutex', r'^ldap_pvt_thread_mutex_t$',
                        LockPrinter)
    printer.add_printer('Sockaddr', r'^Sockaddr$', SockAddrPrinter)
    printer.add_printer('ThreadPool', r'^ldap_pvt_thread_pool_t$',
                        PoolPrinter)

    # pointer printers
    printer.add_pointer_printer('AttributeDescription',
                                r'^AttributeDescription$',
                                AttrDescPrinter)
    printer.add_pointer_printer('ObjectClass', r'^ObjectClass$',
                                OCPrinter)
    printer.add_pointer_printer('Entry', r'^Entry$',
                                EntryPrinter)

    printer.add_pointer_printer('ThreadTask', r'^ldap_int_thread_task_s$',
                                TaskPrinter)
    printer.add_pointer_printer('ThreadPool', r'^ldap_int_thread_poolq_s$',
                                QueuePrinter)

    printer.add_pointer_printer('BackendDB', r'^BackendDB$',
                                DBPrinter)
    printer.add_pointer_printer('Operation', r'^Operation$',
                                OperationPrinter)

    # register pthread aliases if possible
    gdb.post_event(finish_printer)

    if objfile == None:
        objfile = gdb

    gdb.printing.register_pretty_printer(objfile, printer)
