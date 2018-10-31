import gdb

import auto_load._common as helpers
from auto_load._common import SavingDecorator, ignore

class LockDecorator(SavingDecorator):
    """ Show what thread we're waiting on to release the mutex, e.g.

    Thread 3 (Thread 0x7ffff1a12700 (LWP 26872)):
    #2  0x00007ffff7b7c135 in ldap_pvt_thread_mutex_lock [waiting on thread 9 (LWP 27268)] (mutex=0x7ffff26b46a0 <clients_mutex>) at thr_posix.c:307
    #3  0x00007ffff248ca72 in client_destroy (c=Client connid=51566 = {...}) at client.c:544
    #4  0x00007ffff248785f in connection_read_cb (s=33, what=2, arg=0x7fffdc042590) at connection.c:210
    #10 0x00007ffff248f3fe in lloadd_io_task (ptr=0x7fffec0018d0) at daemon.c:1404
    """
    def function(self):
        name = original = super().function()

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

def set_thread_name(name, decorator=None):
    def f(frame, *args, **kwargs):
        gdb.selected_thread().name = name
        if decorator:
            frame = decorator(frame, *args, **kwargs)
        return frame
    return f

class OpenLDAPFrameFilter(helpers.FrameFilter):
    decorators = {
        'ldap_int_thread_pool_wrapper': set_thread_name("worker thread", ignore),

        #'ldap_pvt_thread_cond_wait': ignore,
        'pthread_cond_wait': ignore,

        'ldap_pvt_thread_mutex_lock': LockDecorator,
        'ldap_pvt_thread_mutex_trylock': LockDecorator,
        '__pthread_mutex_cond_lock': LockDecorator,

        'ldap_pvt_thread_pool_submit': ignore,

        #'ldap_pvt_thread_rdwr_rlock': RWLockDecorator,
        #'ldap_pvt_thread_rdwr_rtrylock': RWLockDecorator,
        #'ldap_pvt_thread_rdwr_wlock': RWLockDecorator,
        #'ldap_pvt_thread_rdwr_wtrylock': RWLockDecorator,
    }

def new_objfile(event):
    ff = OpenLDAPFrameFilter()
    event.new_objfile.frame_filters[ff.name] = ff
    print(ff.name+" loaded")
