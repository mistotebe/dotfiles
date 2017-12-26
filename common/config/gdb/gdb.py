import sys
import os.path
from importlib import import_module

print("python version is "+sys.version)

sys.path.append(os.path.expanduser('~/.gdb'))

import deadlock

class ObjFileHandler(object):
    def __init__(self):
        self.loaded_modules = {}
        self.loaded_modules['gdb'] = None

    def __call__(self, event):
        name = event.new_objfile.filename
        basename = os.path.basename(name)
        #print("new objfile loaded: basename: %s, fullname: %s" % (basename, name))
        if basename not in self.loaded_modules:
            try:
                mod = import_module("auto_load." + basename)
                self.loaded_modules[basename] = mod
                f = getattr(mod, "new_objfile")
                if f:
                    f(event)
            except ModuleNotFoundError as e:
                pass

new_objfile_handler = ObjFileHandler()

gdb.events.new_objfile.connect(new_objfile_handler)

deadlock.CommandDeadlockPrint()
