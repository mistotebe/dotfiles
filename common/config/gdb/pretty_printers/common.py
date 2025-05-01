#!/usr/bin/env python3

import gdb
import gdb.printing
import gdb.types

from collections import OrderedDict
from enum import IntFlag


def target_type(value):
    if isinstance(value, gdb.Value):
        value = value.type
    typ = value
    while typ.code is gdb.TYPE_CODE_PTR:
        typ = typ.target()
    return typ


def type_to_fields_dict(typ):
    typ = target_type(typ)
    return {field.name: field for field in typ.fields()}


class NullPrinter:
    def __init__(self, val):
        pass

    def to_string(self):
        return "NULL"


class CollectionPrinter(gdb.printing.RegexpCollectionPrettyPrinter):
    class RegexpPointerSubprinter(gdb.printing.RegexpCollectionPrettyPrinter.
                                  RegexpSubprinter):
        def __init__(self, name, regexp, gen_printer, pointer=False):
            super().__init__(name, regexp, gen_printer)
            self.pointer = pointer

    def __call__(self, val, *args):
        typ = val.type
        pointer = False

        if typ.code == gdb.TYPE_CODE_PTR:
            typ = typ.target()
            pointer = True

        # Get the type name.
        typename = gdb.types.get_basic_type(typ).tag
        if not typename:
            typename = typ.name
        if not typename:
            return None

        for printer in self.subprinters:
            if printer.enabled and printer.pointer == pointer \
                    and printer.compiled_re.search(typename):
                if not val:
                    return NullPrinter(val)
                try:
                    return printer.gen_printer(val, *args)
                except NotImplementedError:
                    pass

        # Fallback to None
        return None

    def add_printer(self, name, regexp, gen_printer, pointer=False):
        self.subprinters.append(
                self.RegexpPointerSubprinter(name, regexp, gen_printer,
                                             pointer)
        )

    def add_pointer_printer(self, name, regexp, gen_printer):
        return self.add_printer(name, regexp, gen_printer, pointer=True)


class StructPrinter:
    def __init__(self, value):
        self.value = value

    def children_dict(self, fields=None):
        value = self.value
        result = OrderedDict()

        if value.type.code == gdb.TYPE_CODE_PTR:
            value = value.dereference()

        if fields is None:
            for field in target_type(value).fields():
                result[field.name] = value[field]
        else:
            for name in fields:
                result[name] = value[name]

        return result

    def children(self):
        return self.children_dict().items()


class AnnotatedStructPrinter(StructPrinter):
    def children_dict(self, fields=None):
        result = super().children_dict(fields)

        exclude = getattr(self, 'exclude', [])
        exclude_false = getattr(self, 'exclude_false', [])
        short = getattr(self, 'short', [])

        for name in list(result.keys()):
            if name in exclude:
                del result[name]
            elif name in exclude_false and not result[name]:
                del result[name]
            elif name in short:
                visualiser = gdb.default_visualizer(result[name])
                if visualiser:
                    result[name] = visualiser.to_string()

        return result

class FlagsPrinter(IntFlag):
    # TODO: allow setting up with prefix(es?) to remove from the returned names

    @classmethod
    def to_string(cls, value, prefix=''):
        result = []
        value = int(value)

        # A mask of 0x0 is a fallback only
        # FIXME: hack to support python 3.6+
        if not value:
            import sys
            if sys.version_info < (3,12):
                if value in cls._value2member_map_:
                    return cls(value).removeprefix(prefix)
            else:
                if value in cls:
                    return cls(value).removeprefix(prefix)

        for mask in cls:
            if mask and (value & mask) == mask:
                value &= ~mask.value
                result.append(mask.name)
        if value:
            result.append(hex(value))

        return '|'.join([name.removeprefix(prefix) for name in result])
