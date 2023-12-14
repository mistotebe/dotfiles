#!/usr/bin/env python3

import gdb
import gdb.printing

from pretty_printers.common import (
    CollectionPrinter, AnnotatedStructPrinter, type_to_fields_dict
)


LDAP_MSG_TAGS = {
    0x60: "Bind request",
    0x42: "Unbind request",
    0x63: "Search request",
    0x66: "Modify request",
    0x68: "Add request",
    0x4a: "Delete request",
    0x6c: "ModRDN request",
    0x6e: "Compare request",
    0x50: "Abandon request",
    0x77: "Extended request",

    0x61: "Bind response",
    0x64: "Search entry",
    0x73: "Search reference",
    0x65: "Search result",
    0x67: "Modify response",
    0x69: "Add response",
    0x6b: "Delete response",
    0x6d: "ModRDN response",
    0x6f: "Compare response",
    0x78: "Extended response",
    0x79: "Intermediate response",
}

class TierPrinter(AnnotatedStructPrinter):
    """Pretty printer for LloadTier"""

    exclude = ['t_name', 't_monitor']
    exclude_false = ['t_backends', 't_flags', 't_private']

    def __init__(self, value, lp=None):
        super().__init__(value)
        self.list = lp or gdb.lookup_symbol('tiers')[0].value()

    def to_string(self):
        if self.value == self.list.address:
            return "end of list"

        return self.value['t_name'] or self.value['t_type']['tier_name']

    def children(self):
        if self.value == self.list.address:
            return []

        result = self.children_dict()
        t = self.value

        result['t_type'] = result['t_type']['tier_name']

        # TODO: convert to proper Queue printers
        address = result['t_backends'].address
        if result['t_backends']['cqh_first'] == address:
            result['t_backends'] = 'empty'
        else:
            desc = gdb.default_visualizer(result['t_backends']['cqh_first'])\
                .to_string()
            if result['t_backends']['cqh_first'] == \
                    result['t_backends']['cqh_last']:
                result['t_backends'] = desc

        next = result['t_next']['stqe_next']
        visualiser = gdb.default_visualizer(next)
        result['next'] = visualiser.to_string()

        del result['t_next']

        return result.items()

class BackendPrinter(AnnotatedStructPrinter):
    """Pretty printer for LloadBackend"""

    exclude = ['b_name', 'b_proto', 'b_port', 'b_host', 'b_retry_tv',
               'b_counters', 'b_monitor']
    exclude_false = ['b_cookie', 'b_dns_req', 'b_connecting',
                     'b_fitness', 'b_weight']

    short = ['b_tier']

    def __init__(self, value, lp=None):
        super().__init__(value)
        if 'b_tier' in type_to_fields_dict(self.value):
            self.list = self.value['b_tier']['t_backends']
        else:
            self.list = lp or gdb.lookup_symbol('backend')[0].value()

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
            result['b_opening'] = "{}+{} failed".format(result['b_opening'],
                                                        result['b_failed'])
        del result['b_failed']

        result['pending_ops'] = "{}/{}".format(result['b_n_ops_executing'],
                                               result['b_max_pending'])
        del result['b_n_ops_executing']
        del result['b_max_pending']

        result['conns'] = "{}/{}".format(result['b_active'],
                                         result['b_numconns'])
        del result['b_active']
        del result['b_numconns']

        result['bind conns'] = "{}/{}".format(result['b_bindavail'],
                                              result['b_numbindconns'])
        del result['b_bindavail']
        del result['b_numbindconns']

        result['b_connecting'] = result['b_connecting']['lh_first']

        prev = result['b_next']['cqe_prev']
        if prev == self.list.address:
            result['prev'] = "end of list"
        elif prev:
            result['prev'] = prev['b_name']

        next = b['b_next']['cqe_next']
        if next == self.list.address:
            result['next'] = "end of list"
        elif next:
            result['next'] = next['b_name']

        del result['b_next']

        # TODO: convert to proper Queue printers
        for name in ['b_conns', 'b_bindconns', 'b_preparing']:
            address = result[name].address
            if result[name]['cqh_first'] == address:
                result[name] = 'empty'
            else:
                desc = gdb.default_visualizer(result[name]['cqh_first'])\
                    .to_string()
                if result[name]['cqh_first'] == result[name]['cqh_last']:
                    result[name] = desc
                else:
                    result[name] = "{}-{}".format(
                        desc, result[name]['cqh_last']['c_connid'])

        for name in ['b_last_conn', 'b_last_bindconn']:
            if result[name]:
                result[name] = gdb.default_visualizer(result[name]).to_string()

        return result.items()


class ConnectionPrinter(AnnotatedStructPrinter):
    exclude = ['c_connid', 'c_destroy', 'c_unlink', 'c_txn', 'c_sb',
               'c_starttime', 'c_activitytime', 'c_peer_name', 'c_vc_cookie',
               'c_pdu_cb', 'c_needs_tls_accept', 'c_counters', 'c_private']
    exclude_false = ['c_read_timeout', 'c_pin_id', 'c_io_state',
                     'c_currentber', 'c_pendingber', 'c_is_tls',
                     'c_sasl_authctx', 'c_sasl_defaults', 'c_sasl_cbinding',
                     'c_restricted', 'c_restricted_at',
                     'c_restricted_inflight', 'c_backend', 'c_linked']
    short = ['c_read_event', 'c_write_event', 'c_backend', 'c_linked']

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
            if 'c_backend' in type_to_fields_dict(self.value):
                backend = value['c_backend']
            else:
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

        if str(result['c_sasl_bind_mech']) == "BVNULL":
            result.pop('c_sasl_bind_mech')

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


class OperationPrinter(AnnotatedStructPrinter):
    exclude = ['o_ber', 'o_request']
    exclude_false = ['o_saved_msgid', 'o_last_response', 'o_freeing',
                     'o_pin_id']
    short = ['o_client', 'o_upstream']

    def to_string(self):
        tag = int(self.value['o_tag'])
        name = LDAP_MSG_TAGS.get(tag, "Unknown message")

        client_msgid = self.value['o_client_msgid'] or \
            self.value['o_saved_msgid']

        text = "{} msgid=({}, {})".format(name, client_msgid,
                                          self.value['o_upstream_msgid'])
        if self.value['o_pin_id']:
            text += " pin={}".format(self.value['o_pin_id'])

        return text

    def children(self):
        result = self.children_dict()

        for side in ['o_client', 'o_upstream']:
            if str(result[side]) != "NULL":
                result.pop(side+'_connid')

            if side+'_live' in result:
                live = result.pop(side+'_live')
                result[side+'_refcnt'] = "{}+{}".format(result[side+'_refcnt'],
                                                        live)

        if int(result['o_tag']) in LDAP_MSG_TAGS:
            result.pop('o_tag')

        if str(result['o_ctrls']) == "BVNULL":
            result.pop('o_ctrls')

        return result.items()


def register(objfile):
    print("registering lloadd printers")
    printer = CollectionPrinter('lloadd')

    # pointer printers
    printer.add_pointer_printer('LloadBackend', r'^LloadBackend$',
                                BackendPrinter)
    printer.add_pointer_printer('LloadTier', r'^LloadTier$',
                                TierPrinter)
    printer.add_pointer_printer('LloadConnection', r'^LloadConnection$',
                                ConnectionPrinter)
    printer.add_pointer_printer('LloadOperation', r'^LloadOperation$',
                                OperationPrinter)

    if objfile is None:
        objfile = gdb

    gdb.printing.register_pretty_printer(objfile, printer)
