import gdb

import auto_load._common as helpers
from auto_load._common import ignore
from auto_load.libpthread import LockDecorator


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
