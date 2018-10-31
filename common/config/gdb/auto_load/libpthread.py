import gdb

import auto_load._common as helpers
from auto_load._common import ignore

class PThreadFrameFilter(helpers.FrameFilter):
    drop_prefixes = ['__pthread_']
    decorators = {
        'start_thread': ignore,
        'futex_wait_cancelable': ignore,
    }

def new_objfile(event):
    ff = PThreadFrameFilter()
    event.new_objfile.frame_filters[ff.name] = ff
    print(ff.name+" loaded")
