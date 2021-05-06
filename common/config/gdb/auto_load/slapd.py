import auto_load._common as helpers
from auto_load._common import ignore


class SlapdFrameFilter(helpers.FrameFilter):
    decorators = {
        'over_op_func': ignore,
        'overlay_op_walk': ignore,
    }


def new_objfile(event):
    ff = SlapdFrameFilter()
    event.new_objfile.frame_filters[ff.name] = ff
    print(ff.name+" loaded")
