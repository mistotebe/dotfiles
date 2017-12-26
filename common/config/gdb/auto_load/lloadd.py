import gdb
from gdb.FrameDecorator import FrameDecorator

print("Loading lloadd support")

def ignore(frame, frame_iterator):
    return None

def set_thread_name(name, decorator=None):
    def f(frame, *args, **kwargs):
        gdb.selected_thread().name = name
        if decorator:
            frame = decorator(frame, *args, **kwargs)
        return frame
    return f

class LockDecorator(FrameDecorator):
    def __init__(self, frame, frame_iterator):
        super(LockDecorator, self).__init__(frame)
        self.frame = frame
        self.frame_iterator = frame_iterator
        self.thread = gdb.selected_thread()

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

decorators = {
    'clone': ignore,
    'start_thread': ignore,
    'ldap_int_thread_pool_wrapper': set_thread_name("worker thread", ignore),

    #'ldap_pvt_thread_cond_wait': ignore,

    '__lll_lock_wait': ignore,
    '__GI___pthread_mutex_lock': ignore,

    'futex_wait_cancelable': ignore,
    '__pthread_cond_wait': ignore,
    '__pthread_cond_wait_common': ignore,

    'ldap_pvt_thread_mutex_lock': LockDecorator,
    'ldap_pvt_thread_mutex_trylock': LockDecorator,

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
            if frame:
                yield frame

def new_objfile(event):
    ff = LLoadFrameFilter()
    event.new_objfile.frame_filters[ff.name] = ff
    print(ff.name+" loaded")
