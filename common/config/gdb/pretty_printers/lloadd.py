#!/usr/bin/env python3

import gdb
import gdb.printing

from pretty_printers.common import CollectionPrinter, AnnotatedStructPrinter

class BackendPrinter(AnnotatedStructPrinter):
    """Pretty printer for LloadBackend"""

    exclude = ['b_name', 'b_proto', 'b_port', 'b_host', 'b_retry_tv', 'b_counters']

    def __init__(self, value, l=None):
        super().__init__(value)
        self.list = l or gdb.lookup_symbol('backend')[0].value()

    def to_string(self):
        if self.value == self.list.address:
            return "end of list"

        return self.value['b_name']

    def children(self):
        if self.value == self.list.address:
            return []

        result = self.children_dict()
        b = self.value

        if result['b_failed']:
            result['b_opening'] = "{}+{} failed".format(result['b_opening'], result['b_failed'])
        del result['b_failed']

        result['pending_ops'] = "{}/{}".format(result['b_n_ops_executing'], result['b_max_pending'])
        del result['b_n_ops_executing']
        del result['b_max_pending']

        result['conns'] = "{}/{}".format(result['b_active'], result['b_numconns'])
        del result['b_active']
        del result['b_numconns']

        result['bind conns'] = "{}/{}".format(result['b_bindavail'], result['b_numbindconns'])
        del result['b_bindavail']
        del result['b_numbindconns']

        result['b_connecting'] = result['b_connecting']['lh_first']

        prev = result['b_next']['cqe_prev']
        if prev == self.list.address:
            result['prev'] = "end of list"
        else:
            result['prev'] = prev['b_name']

        next = b['b_next']['cqe_next']
        if next == self.list.address:
            result['next'] = "end of list"
        else:
            result['next'] = next['b_name']

        del result['b_next']

        # TODO: convert to proper Queue printers
        for name in ['b_conns', 'b_bindconns', 'b_preparing']:
            address = b[name].address
            if result[name]['cqh_first'] == address:
                result[name] = 'empty'
            else:
                desc = ConnectionPrinter(result[name]['cqh_first']).to_string()
                if result[name]['cqh_first'] == result[name]['cqh_last']:
                    result[name] = desc
                else:
                    result[name] = "{}-{}".format(desc, result[name]['cqh_last']['c_connid'])

        for name in ['b_last_conn', 'b_last_bindconn']:
            if result[name]:
                result[name] = ConnectionPrinter(result[name]).to_string()

        return result.items()

class ConnectionPrinter(AnnotatedStructPrinter):
    exclude = ['c_connid', 'c_destroy', 'c_txn', 'c_sb', 'c_starttime',
            'c_activitytime', 'c_peer_name', 'c_vc_cookie', 'c_pdu_cb',
            'c_needs_tls_accept', 'c_counters', 'c_private']
    exclude_false = ['c_pin_id', 'c_currentber', 'c_pendingber']
    short = ['c_read_event', 'c_write_event']

    def conn_type(self, value=None):
        value = value or self.value
        parent = None
        desc = None

        cb = value['c_destroy']
        if not cb:
            value.type = "No connection"
        if cb == gdb.lookup_symbol('client_destroy')[0].value():
            desc = "Client"
            parent = gdb.lookup_symbol('clients')[0].value()
        elif cb == gdb.lookup_symbol('upstream_destroy')[0].value():
            desc = "Upstream"
            backend_type = gdb.lookup_type("LloadBackend").pointer()
            backend = value['c_private'].cast(backend_type)

            if str(value['c_type']) == 'LLOAD_C_BIND':
                desc = "Upstream bind"
                parent = backend['b_bindconns'].address
            elif str(value['c_type']) == 'LLOAD_C_PREPARING':
                desc = "Upstream preparing"
                parent = backend['b_preparing'].address
            else:
                parent = backend['b_conns'].address

        elif cb == gdb.lookup_symbol('connection_destroy')[0].value():
            desc = "Connection"

        return desc, parent

    def to_string(self, value=None):
        value = value or self.value
        desc, _ = self.conn_type(value)
        return "{} connid={}".format(desc, value['c_connid'])

    def children(self):
        result = self.children_dict()

        live = result.pop('c_live')
        result['c_refcnt'] = "{}+{}".format(result['c_refcnt'], live)

        _, parent = self.conn_type()
        if parent:
            prev = result['c_next']['cqe_prev']
            if prev == parent.address:
                result['prev'] = "end of list"
            else:
                result['prev'] = "connid={}".format(prev['c_connid'])

            next = result['c_next']['cqe_next']
            if next == parent.address:
                result['next'] = "end of list"
            else:
                result['next'] = "connid={}".format(next['c_connid'])

        del result['c_next']

        return result.items()


def register(objfile):
    print("registering lloadd printers")
    printer = CollectionPrinter('lloadd')

    # pointer printers
    printer.add_pointer_printer('LloadBackend', r'^LloadBackend$',
                                BackendPrinter)
    printer.add_pointer_printer('LloadConnection', r'^LloadConnection$',
                                ConnectionPrinter)

    if objfile == None:
        objfile = gdb

    gdb.printing.register_pretty_printer(objfile, printer)
