import auto_load._common as helpers
from auto_load._common import GDBArgument, SavingDecorator, ignore


class AssertDecorator(SavingDecorator):
    def function(self):
        return "failing assertion"

    def frame_args(self):
        assertion = self.inferior_frame().read_var('assertion')
        return [GDBArgument('assertion', assertion)]

    def filename(self):
        pass

    def line(self):
        pass


class LibCFrameFilter(helpers.FrameFilter):
    drop_prefixes = [ '__GI_', '__lll_', '_IO_' ]
    decorators = {
        '__GI___assert_fail': AssertDecorator,
        '__assert_fail_base': ignore,

        'clone': ignore,
    }


def new_objfile(event):
    ff = LibCFrameFilter()
    event.new_objfile.frame_filters[ff.name] = ff
    print(ff.name+" loaded")
