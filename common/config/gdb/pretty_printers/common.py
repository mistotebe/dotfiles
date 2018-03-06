#!/usr/bin/env python3

import gdb
import gdb.printing
import gdb.types

class CollectionPrinter(gdb.printing.RegexpCollectionPrettyPrinter):
    def __init__(self, *args, **kwargs):
        super(CollectionPrinter, self).__init__(*args, **kwargs)

    class RegexpPointerSubprinter(gdb.printing.RegexpCollectionPrettyPrinter.RegexpSubprinter):
        def __init__(self, name, regexp, gen_printer, pointer=False):
            super(CollectionPrinter.RegexpPointerSubprinter, self).__init__(name, regexp, gen_printer)
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
                return printer.gen_printer(val)

        # Fallback to None
        return None

    def add_printer(self, name, regexp, gen_printer, pointer=False):
        self.subprinters.append(
                self.RegexpPointerSubprinter(name, regexp, gen_printer, pointer)
        )

    def add_pointer_printer(self, name, regexp, gen_printer):
        return self.add_printer(name, regexp, gen_printer, pointer=True)
