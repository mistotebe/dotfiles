#!/usr/bin/env python3

import gdb
import gdb.printing

import socket
from decimal import Decimal

from pretty_printers.common import CollectionPrinter


AF_UNIX = 1
AF_INET = 2
AF_INET6 = 10


class TimevalPrinter:
    """Pretty printer for timeval."""
    def __init__(self, value):
        self.sec = Decimal(int(value['tv_sec']))
        self.usec = Decimal(int(value['tv_usec']))
        self.tv = self.sec + self.usec / 1000000

    def to_string(self):
        if abs(self.tv) >= 1:
            return "{}s".format(self.tv.to_eng_string())
        else:
            return "{}ms".format((self.tv * 1000).to_eng_string())


class SockAddrPrinterGeneric:
    __family_to_subclass__ = {}

    prefix = 'sa_'
    typename = 'struct sockaddr'

    def __init_subclass__(cls, **kwargs):
        family = getattr(cls, 'family', None)
        if family:
            __class__.__family_to_subclass__[family] = cls

    def __new__(cls, value):
        if cls is not __class__:
            return super().__new__(cls)

        family = int(value[cls.prefix + 'family'])
        subclass = cls.__family_to_subclass__.get(family)
        if subclass:
            value = value.cast(gdb.lookup_type(cls.typename))
            return subclass.__new__(subclass, value)

        raise NotImplementedError

    def __init__(self, value):
        if value.type.name != self.typename:
            value = value.cast(gdb.lookup_type(self.typename))
        self.value = value


class SockAddrPrinterIP(SockAddrPrinterGeneric):
    def __init__(self, value):
        super().__init__(value)
        assert self.family == self.value[self.prefix + 'family']
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
    family = AF_INET
    addr_len = 4
    prefix = 'sin_'
    name = 'IPv4'
    typename = 'struct sockaddr_in'


class SockAddrPrinterIPv6(SockAddrPrinterIP):
    family = AF_INET6
    addr_len = 16
    prefix = 'sin6_'
    name = 'IPv6'
    typename = 'struct sockaddr_in6'

    def to_string(self):
        return "{}=[{}]:{}".format(self.name, self.address(), self.port())

    def children(self):
        result = {}
        if self.value[self.prefix + 'flowinfo']:
            result['flow id'] = socket.ntohs(self.value[self.prefix + 'flowinfo'])

        if self.value[self.prefix + 'scope_id']:
            result['scope id'] = socket.ntohs(self.value[self.prefix + 'scope_id'])

        return result.items()


class SockAddrPrinterUnix(SockAddrPrinterGeneric):
    family = AF_UNIX
    name = 'UNIX'
    typename = 'struct sockaddr_un'

    def __init__(self, value):
        super().__init__(value)
        self.family = self.value['sun_family']

    def to_string(self):
        address = self.value['sun_path']
        return "{}={}".format(self.name, address)


def register(objfile):
    printer = CollectionPrinter('POSIX')

    printer.add_printer('struct timeval', r'^timeval$', TimevalPrinter)
    printer.add_printer('sockaddr_in', r'^sockaddr_in$', SockAddrPrinterIPv4)
    printer.add_printer('sockaddr_in6', r'^sockaddr_in6$', SockAddrPrinterIPv6)
    printer.add_printer('sockaddr_un', r'^sockaddr_un$', SockAddrPrinterUnix)
    printer.add_printer('sockaddr', r'^sockaddr$', SockAddrPrinterGeneric)

    printer.add_pointer_printer('struct timeval', r'^timeval$', TimevalPrinter)

    if objfile == None:
        objfile = gdb

    gdb.printing.register_pretty_printer(objfile, printer)
