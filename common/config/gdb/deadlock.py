#!/usr/bin/env python3

import gdb

class ThreadEntry:
    def __init__(self, thread):
        # create a context manager for thread, frame is not valid unless we
        # select its thread
        saved_thread = gdb.selected_thread()

        self.thread = thread

        self.thread.switch()
        self.frame = gdb.newest_frame()

        self.pid, self.lwp_id, _ = thread.ptid

    def __hash__(self):
        return self.lwp_id

    def __repr__(self):
        return "Thread #{thread.num} (LWP {self.lwp_id})".format(self=self, thread=self.thread, frame=self.frame)

class WaiterEntry(ThreadEntry):
    FLAG_STRANDED = 1 << 0
    FLAG_SELF_LOCKED = 1 << 1

    def __init__(self, thread):
        super(WaiterEntry, self).__init__(thread)

        self._flags = 0

        self.owner_lwp_id = None
        self.root = None
        self.children = set()

        if self.frame.name() == '__lll_lock_wait':
            self.mutex = self.frame.older().read_var('mutex')
            self.owner_lwp_id = int(self.mutex['__data']['__owner'])
            self.frame = self.frame.older().older()

            if self.frame.name() == 'ldap_pvt_thread_mutex_lock':
                self.frame = self.frame.older()
        else:
            self.root = self.lwp_id

        if self.lwp_id == self.owner_lwp_id:
            self._flags |= self.FLAG_SELF_LOCKED
            self.root = self.lwp_id

    def __repr__(self):
        self.thread.switch()
        sal = self.frame.find_sal()

        fmt = "Thread #{thread.num} (LWP {self.lwp_id})"
        if self.frame.name():
            fmt += " in {name}()"
        if sal.is_valid():
            fmt += " at {sal.symtab.filename}:{sal.line}"
        if self._flags & self.FLAG_STRANDED:
            fmt += " (waiting on a nonexistent thread LWP {self.owner_lwp_id})"
        if self._flags & self.FLAG_SELF_LOCKED:
            fmt += " (waiting on itself)"

        return fmt.format(self=self, thread=self.thread, frame=self.frame, name=self.frame.name(), sal=sal)

class LockGraph:
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
    """Prints threads that participate in a deadlock"""

    def __init__(self):
        super(CommandDeadlockPrint, self).__init__("deadlock", gdb.COMMAND_USER)
        print("Command 'deadlock' loaded")

    def invoke(self, arg, from_tty):
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

        saved_thread.switch()

    def print_deps(self, thread, depth=0, root=None):
        if root == thread:
            print("\t" * depth + "deadlock from root")
        else:
            print("\t" * depth + repr(thread))
            for child in thread.children:
                self.print_deps(child, depth+1, root or thread)

