#!/usr/bin/env python3

import auto_load._common as helpers
from auto_load._common import ignore


class LloadFrameFilter(helpers.FrameFilter):
    decorators = {
        'lload_base_dispatch': ignore,
        'lload_start_daemon': ignore,

        'handle_pdus': ignore,
    }


def new_objfile(event):
    ff = LloadFrameFilter()
    event.new_objfile.frame_filters[ff.name] = ff
    print(ff.name+" loaded")
