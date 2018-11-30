#!/usr/bin/env python3

import gdb

class ThreadEntry:
    "Representable thread object"

    def __init__(self, thread):
        saved_thread = gdb.selected_thread()

        self.thread = thread

        self.thread.switch()
        self.frame = gdb.newest_frame()

        self.pid, self.lwp_id, _ = thread.ptid

        if not saved_thread:
            saved_thread.switch()

    def __hash__(self):
        return self.lwp_id

    def __repr__(self):
        return "Thread #{thread.num} (LWP {self.lwp_id})".format(self=self, thread=self.thread)

class WaiterEntry(ThreadEntry):
    "Thread object representing a vertex+its outbound edges in a LockGraph"

    FLAG_STRANDED = 1 << 0
    FLAG_SELF_LOCKED = 1 << 1

    def __init__(self, thread):
        saved_thread = gdb.selected_thread()
        super().__init__(thread)
        self.thread.switch()

        self._flags = 0

        self.owner_lwp_id = None
        self.root = None
        self.children = set()
        self.mutex = None

        if not self._populate(self.frame.name()):
            self.root = self.lwp_id

        if self.lwp_id == self.owner_lwp_id:
            self._flags |= self.FLAG_SELF_LOCKED
            self.root = self.lwp_id

        if not saved_thread:
            saved_thread.switch()

    def __repr__(self):
        self.thread.switch()
        sal = self.frame.find_sal()

        fmt = "Thread #{thread.num} (LWP {self.lwp_id})"
        if self.frame.name():
            fmt += " in {name}()"
        if sal.is_valid() and sal.symtab and sal.symtab.is_valid():
            fmt += " at {sal.symtab.filename}:{sal.line}"
        if self._flags & self.FLAG_STRANDED:
            fmt += " (waiting on a nonexistent thread LWP {self.owner_lwp_id})"
        if self._flags & self.FLAG_SELF_LOCKED:
            fmt += " (waiting on itself)"

        return fmt.format(self=self, thread=self.thread, frame=self.frame,
                          name=self.frame.name(), sal=sal)

    def _populate(self, name):
        if name == '__pthread_mutex_lock_full':
            self.mutex = self.frame.read_var('mutex')
            self.frame = self.frame.older()
        elif name == '__lll_lock_wait':
            self.mutex = self.frame.older().read_var('mutex')
            self.frame = self.frame.older().older()
            if self.frame.name() == 'ldap_pvt_thread_mutex_lock':
                self.frame = self.frame.older()
        else:
            return None

        self.owner_lwp_id = int(self.mutex['__data']['__owner'])
        return self.owner_lwp_id

class LockGraph:
    "Generate the lock waiting graph for a given inferior"

    def __init__(self, inferior):
        self.inferior = inferior
        self.threads = {}
        self.roots = set()
        self.cycles = set()

        self._todo = set()
        for t in self.inferior.threads():
            thread = WaiterEntry(t)
            self.threads[thread.lwp_id] = thread
            if thread.root:
                self.roots.add(thread)
            else:
                self._todo.add(thread)

        while self._todo:
            self._resolve(self._todo.pop())

    def _resolve(self, thread):
        assert thread.root is None, "thread %d has already been resolved" % thread.lwp_id
        self._todo.discard(thread)

        parent = self.threads.get(thread.owner_lwp_id)
        if not parent:
            self.roots.add(thread)
            thread.root = thread.lwp_id
            if thread.owner_lwp_id:
                thread._flags |= thread.FLAG_STRANDED
            return thread.root

        thread.parent = parent
        parent.children.add(thread)

        if parent.root:
            thread.root = parent.root
        else:
            if parent in self._todo:
                thread.root = self._resolve(parent)
            else:
                # we have just hit a cycle, parent is being resolved somewhere
                # up the stack
                thread.root = parent.lwp_id
                self.cycles.add(parent)

        return thread.root

class CommandDeadlockPrint(gdb.Command):
    """Prints threads that participate in a deadlock, e.g.
    (gdb) deadlock
    Cycles:
    Thread #3 (LWP 26872) in client_destroy() at client.c:544
            Thread #9 (LWP 27268) in connections_walk() at connection.c:387
                    deadlock from root
                    Thread #4 (LWP 26873) in client_init() at client.c:414

    In the above, thread #3 is blocked waiting on a lock that thread #9 holds
    and vice versa. Thread #4 is blocked waiting on thread #9 to unlock
    something as well.
    """

    def __init__(self):
        super().__init__("deadlock", gdb.COMMAND_USER)
        print("Command 'deadlock' loaded")

    def invoke(self, arg, from_tty):
        "Resolves and prints deadlocks"

        saved_thread = gdb.selected_thread()
        graph = LockGraph(gdb.selected_inferior())

        for root in graph.roots:
            if root.owner_lwp_id or root.children:
                self.print_deps(root)
                print()

        if graph.cycles:
            print("Cycles:")
        for cycle in graph.cycles:
            self.print_deps(cycle)
            print()

        if saved_thread:
            saved_thread.switch()

    def print_deps(self, thread, depth=0, root=None):
        "Print the part of the component related to thread (anchored at root)"

        if root == thread:
            print("\t" * depth + "deadlock from root")
        else:
            print("\t" * depth + repr(thread))
            for child in thread.children:
                self.print_deps(child, depth+1, root or thread)
