#!/usr/bin/env python3

import gdb
import gdb.printing
import gdb.types

from collections import OrderedDict

class NullPrinter:
    def __init__(self, val):
        pass

    def to_string(self):
        return "NULL"

class CollectionPrinter(gdb.printing.RegexpCollectionPrettyPrinter):
    class RegexpPointerSubprinter(gdb.printing.RegexpCollectionPrettyPrinter.RegexpSubprinter):
        def __init__(self, name, regexp, gen_printer, pointer=False):
            super().__init__(name, regexp, gen_printer)
            self.pointer = pointer

    def __call__(self, val):
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
                #print("Selecting printer", printer.name, "for", "pointer" if pointer else "non-pointer", "type", val.type)
                if not val:
                    return NullPrinter(val)
                return printer.gen_printer(val)

        # Fallback to None
        return None

    def add_printer(self, name, regexp, gen_printer, pointer=False):
        self.subprinters.append(
                self.RegexpPointerSubprinter(name, regexp, gen_printer, pointer)
        )

    def add_pointer_printer(self, name, regexp, gen_printer):
        return self.add_printer(name, regexp, gen_printer, pointer=True)

class StructPrinter:
    def __init__(self, value):
        self.value = value

    def children_dict(self, fields=None):
        pointer = self.value
        value = pointer.dereference()
        result = OrderedDict()

        if fields is None:
            for field in value.type.fields():
                result[field.name] = value[field.name]
        else:
            for name in fields:
                result[name] = value[name]

        return result

class AnnotatedStructPrinter(StructPrinter):
    def children_dict(self, fields=None):
        result = super().children_dict(fields)

        exclude = getattr(self, 'exclude', [])
        exclude_false = getattr(self, 'exclude_false', [])
        short = getattr(self, 'short', [])

        for name in exclude:
            result.pop(name, None)

        for name in exclude_false:
            if name in result and not result[name]:
                del result[name]

        for name in short:
            result[name] = gdb.default_visualizer(result[name]).to_string()

        return result
