import auto_load._common as helpers
from auto_load._common import ignore

from pretty_printers.libevent import register


class LibEventFrameFilter(helpers.FrameFilter):
    decorators = {
        'event_base_loop': ignore,
        'epoll_dispatch': ignore,

        'event_persist_closure': ignore,
        'event_process_active_single_queue': ignore,
        'event_process_active': ignore,
    }


def new_objfile(event):
    ff = LibEventFrameFilter()
    event.new_objfile.frame_filters[ff.name] = ff
    print(ff.name+" loaded")
    register(event.new_objfile)
