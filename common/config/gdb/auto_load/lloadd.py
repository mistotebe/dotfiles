#!/usr/bin/env python3

import gdb
from gdb.FrameDecorator import FrameDecorator

print("Loading lloadd support")

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
        super(SavingDecorator, self).__init__(frame)
        self.frame = frame
        self.frame_iterator = frame_iterator
        self.thread = gdb.selected_thread()

def ignore(frame, frame_iterator):
    return None

def set_thread_name(name, decorator=None):
    def f(frame, *args, **kwargs):
        gdb.selected_thread().name = name
        if decorator:
            frame = decorator(frame, *args, **kwargs)
        return frame
    return f

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

class LockDecorator(SavingDecorator):
    def function(self):
        name = original = super(LockDecorator, self).function()

        frame = self.inferior_frame()
        mutex = frame.read_var('mutex')
        owner = mutex['__data']['__owner']

        if owner == self.thread.ptid[1]:
            name = "self-deadlock in " + name
        else:
            for thread in self.thread.inferior.threads():
                lwp_id = thread.ptid[1]
                if lwp_id == owner:
                    name += " [waiting on thread %d (LWP %d)]" % (thread.num, lwp_id)
                    break

        return name

drop_prefixes = [ '__GI_', '__lll_', '_IO_', '__pthread_' ]
decorators = {
    'clone': ignore,
    'start_thread': ignore,
    'ldap_int_thread_pool_wrapper': set_thread_name("worker thread", ignore),

    #'ldap_pvt_thread_cond_wait': ignore,

    'event_base_loop': ignore,
    'epoll_dispatch': ignore,
    'lload_base_dispatch': ignore,
    'lload_start_daemon': ignore,

    'event_persist_closure': ignore,
    'event_process_active_single_queue': ignore,
    'event_process_active': ignore,

    '__GI___assert_fail': AssertDecorator,

    'futex_wait_cancelable': ignore,

    'ldap_pvt_thread_mutex_lock': LockDecorator,
    'ldap_pvt_thread_mutex_trylock': LockDecorator,
    '__pthread_mutex_cond_lock': LockDecorator,

    'ldap_pvt_thread_pool_submit': ignore,

    'handle_pdus': ignore,

#    'ldap_pvt_thread_rdwr_rlock': RWLockDecorator,
#    'ldap_pvt_thread_rdwr_rtrylock': RWLockDecorator,
#    'ldap_pvt_thread_rdwr_wlock': RWLockDecorator,
#    'ldap_pvt_thread_rdwr_wtrylock': RWLockDecorator,
}

class LLoadFrameFilter:
    def __init__(self):
        self.name = "LLoadFrameFilter"
        self.priority = 100
        self.enabled = True

    def filter(self, frame_iterator):
        for frame in frame_iterator:
            name = frame.inferior_frame().name()
            decorator = decorators.get(name)
            if decorator:
                frame = decorator(frame, frame_iterator)
            else:
                for prefix in drop_prefixes:
                    if name.startswith(prefix):
                        frame = None
                        break
            if frame:
                yield frame

def new_objfile(event):
    ff = LLoadFrameFilter()
    event.new_objfile.frame_filters[ff.name] = ff
    print(ff.name+" loaded")
