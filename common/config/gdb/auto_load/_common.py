import gdb
from gdb.FrameDecorator import FrameDecorator


class GDBArgument:
    def __init__(self, name, value):
        self._name = name
        self._value = value

    def symbol(self):
        return self._name

    def value(self):
        return self._value


class SavingDecorator(FrameDecorator):
    def __init__(self, frame, frame_iterator):
        super().__init__(frame)
        self.frame = frame
        self.frame_iterator = frame_iterator
        self.thread = gdb.selected_thread()


def ignore(frame, frame_iterator):
    return None


class FrameFilter:
    drop_prefixes = []
    decorators = {}

    def __init__(self, name=None, priority=100, enabled=True, objfile=None):
        self.name = name or self.__class__.__name__
        self.priority = priority
        self.enabled = enabled
        self.objfile = objfile

    def filter(self, frame_iterator):
        for frame in frame_iterator:
            name = frame.inferior_frame().name()
            if not name:
                yield frame
                continue

            if name.find('@@') >= 0:
                name = name[:name.find('@@')]

            for prefix in self.drop_prefixes:
                if name.startswith(prefix):
                    name = name[len(prefix):]
                    break
            else:
                prefix = None

            decorator = self.decorators.get(name)
            if decorator:
                frame = decorator(frame, frame_iterator)
            elif prefix is not None:
                frame = None

            if frame:
                yield frame
