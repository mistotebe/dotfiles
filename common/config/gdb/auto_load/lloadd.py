#!/usr/bin/env python3

import auto_load._common as helpers
from auto_load._common import GDBArgument, SavingDecorator, ignore


class LloadFrameFilter(helpers.FrameFilter):
    decorators = {
        'lload_base_dispatch': ignore,
        'lload_start_daemon': ignore,
    }


class EpochDecorator(SavingDecorator):
    def frame_args(self):
        args = super().frame_args()
        if any(str(arg.symbol()) == 'epoch' for arg in args):
            return args

        try:
            epoch = self.inferior_frame().read_var('epoch')
            args.append(GDBArgument('_epoch', epoch))
        except ValueError:
            pass
        return args


class EpochFrameFilter(helpers.FrameFilter):
    def filter(self, frame_iterator):
        for frame in frame_iterator:
            try:
                symtab = frame.inferior_frame().find_sal().symtab
                if not symtab:
                    pass
                elif self.objfile and symtab.objfile != self.objfile:
                    pass
                else:
                    frame = EpochDecorator(frame, frame_iterator)
            except Exception:
                pass
            finally:
                yield frame


def new_objfile(event):
    ff = EpochFrameFilter(objfile=event.new_objfile)
    event.new_objfile.frame_filters[ff.name] = ff
    print(ff.name+" loaded")

    ff = LloadFrameFilter()
    event.new_objfile.frame_filters[ff.name] = ff
    print(ff.name+" loaded")
