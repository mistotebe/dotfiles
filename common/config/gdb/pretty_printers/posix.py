#!/usr/bin/env python3

import gdb
import gdb.printing

import socket

from pretty_printers.common import CollectionPrinter

class TimevalPrinter:
    """Pretty printer for timeval."""
    def __init__(self, value):
        self.sec = value['tv_sec']
        self.usec = value['tv_usec']
        self.tv = self.sec + self.usec / 1000000.0

    def to_string(self):
        if self.usec:
            return "{}s".format(self.tv)
        else:
            return "{}s".format(self.sec)

AF_UNIX = 1
AF_INET = 2
AF_INET6 = 10

class SockAddrPrinterIP:
    def __init__(self, value):
        self.value = value
        self.family = value[self.prefix + 'family']
        self.addr_type = gdb.lookup_type("char").array(self.addr_len-1)

    def address(self):
        address_buf = self.value[self.prefix + 'addr'].cast(self.addr_type)
        address = bytes([int(address_buf[x]) for x in range(self.addr_len)])

        return socket.inet_ntop(self.family, address)

    def port(self):
        return socket.ntohs(self.value[self.prefix + 'port'])

    def to_string(self):
        return "{}={}:{}".format(self.name, self.address(), self.port())

class SockAddrPrinterIPv4(SockAddrPrinterIP):
    addr_len = 4
    prefix = 'sin_'
    name = 'IPv4'

class SockAddrPrinterIPv6(SockAddrPrinterIP):
    addr_len = 16
    prefix = 'sin6_'
    name = 'IPv6'

    def to_string(self):
        return "{}=[{}]:{}".format(self.name, self.address(), self.port())

    def children(self):
        result = {}
        if self.value[self.prefix + 'flowinfo']:
            result['flow id'] = socket.ntohs(self.value[self.prefix + 'flowinfo'])

        if self.value[self.prefix + 'scope_id']:
            result['scope id'] = socket.ntohs(self.value[self.prefix + 'scope_id'])

        return result.items()

class SockAddrPrinterUnix:
    def __init__(self, value):
        self.value = value
        self.family = value['sun_family']

    def to_string(self):
        address = self.value['sun_path']
        return "UNIX={}".format(address)

def register(objfile):
    printer = CollectionPrinter('POSIX')

    printer.add_printer('struct timeval', r'^timeval$', TimevalPrinter)
    printer.add_printer('sockaddr_in', r'^sockaddr_in$', SockAddrPrinterIPv4)
    printer.add_printer('sockaddr_in6', r'^sockaddr_in6$', SockAddrPrinterIPv6)
    printer.add_printer('sockaddr_un', r'^sockaddr_un$', SockAddrPrinterUnix)

    if objfile == None:
        objfile = gdb

    gdb.printing.register_pretty_printer(objfile, printer)
