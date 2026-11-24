#!/usr/bin/env python3

import sys
import os.path
from importlib import import_module

print("python version is "+sys.version)

sys.path.append(os.path.expanduser('~/.gdb'))

import gdb

import pretty_printers
import deadlock


# We can't set scheduler-locking without a backend, so do this on the
# first stop (only!)
def _sl(event):
    try:
        gdb.execute("set scheduler-locking step", to_string=True)
        gdb.events.stop.disconnect(_sl)
    except gdb.error:
        pass


gdb.events.stop.connect(_sl)


class ObjFileHandler:
    def __init__(self):
        self.loaded_modules = {}
        self.loaded_modules['gdb'] = None

    def __call__(self, event):
        name = event.new_objfile.filename
        basename = os.path.basename(name)
        basename = basename.split('.')[0]
        if basename.startswith("lt-"):
            basename = basename.split('-', 1)[1]
        basename = basename.split('-')[0]

        mod = self.loaded_modules.get(basename)
        if not mod:
            try:
                mod = import_module("auto_load." + basename)
                self.loaded_modules[basename] = mod
            except ImportError:
                return
        f = getattr(mod, "new_objfile")
        if f:
            f(event)


new_objfile_handler = ObjFileHandler()

gdb.events.new_objfile.connect(new_objfile_handler)

# TODO: remaining printers until we can detect statically loaded libraries
pretty_printers.register()

deadlock.CommandDeadlockPrint()
