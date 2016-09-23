from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import
from builtins import super
from builtins import str
from builtins import int
from future import standard_library
standard_library.install_aliases()

import logging
import subprocess
import os
import time
import signal
import threading
from queue import Queue

import angr
import simuvex
from simuvex.plugin import SimInspector, BP

from avatar.system import EVENT_RUNNING, EVENT_STOPPED, EVENT_BREAKPOINT, EVENT_END_STEPPING
from avatar.debuggable import Breakpoint
from avatar.emulators.angr.configuration import AngrConfiguration

log = logging.getLogger(__name__)

class AngrBreakpoint(Breakpoint):
    _defined_bkpts = dict()
    _count = 0

    def __init__(self, system, bkpt, address):
        super().__init__()
        self._system = system
        self._bkpt = bkpt
        self._queue = Queue()
        self._number = AngrBreakpoint._count
        self._address = address
        AngrBreakpoint._count += 1
        system.register_event_listener(self._event_receiver)
        _defined_bkpts[address] = self

    def wait(self, timeout = None):
        if self._handler:
            raise Exception("Breakpoint cannot have a handler and be waited on")

        if timeout == 0:
            return self._queue.get()
        else:
            return self._queue.get(True, timeout)

    def delete(self):
        self._system.unregister_event_listener(self._event_receiver)
        del AngrBreakpoint._defined_bkpts[address]
        emulator = self._system.get_emulator()
        if emulator.is_running():
            emulator.stop()
            emulator._path.state.inspect.remove_breakpoint(self._bkpt)
            emulator.cont()
        else:
            emulator._path.state.inspect.remove_breakpoint(self._bkpt)

    @staticmethod
    def _on_angr_breakpoint_fire(state):
        addr = state.regs.ip
        bkpt = AngrBreakpoint._defined_bkpts[addr]
        evt =  {"tags": [EVENT_STOPPED, EVENT_BREAKPOINT],
                "properties": {
                    "address": address,
                    "bkpt_number": bkpt._num
                    },
                "channel": "angr",
                "source": "emulator"
               }
        bkpt._system.post_event(evt)

    def _event_receiver(self, evt):
        if EVENT_BREAKPOINT in evt["tags"] and \
                evt["source"] == "emulator" and \
                evt["properties"]["bkpt_number"] == self._num:
            if self._handler:
                self._handler(self._system, self)
            else:
                self._queue.put(evt)

class AngrEmulator(Emulator):
    def __init__(self, system):
        super().__init__(system)
        self._configuration = AngrConfiguration(self._system.get_configuration())

    def init(self):
        self._configuration.write_configuration_files(
            self._system.get_configuration()["output_directory"])

    def start(self):
        log.info("Starting simuvex thread")
        self._angr_thread = threading.Thread(target = self.run_angr)
        self._thread_exit = threading.Event()
        self._thread_can_run = threading.Event()
        self._thread_dead = threading.Event()
        self._thread_stopped = threading.Event()

        #TODO: specify new CLE backend when it will be ready
        self._angr_project = angr.Project(self._configuration["binary_file"])

        self._angr_thread.start()

    def is_running(self):
        return self._thread_can_run.is_set()

    def cont(self):
        self._thread_can_run.set()

    def stop(self):
        self._thread_can_run.clear()
        self._thead_stopped.wait()

    def exit(self):
        self._thread_exit.set()
        self._thread_dead.wait()

    def run_angr(self):
        #create path
        self._path = self._angr_project.factory.path()

        while True:
            self.stopped.set()
            self._thread_can_run.wait()
            self.stopped.clear()
            if self._thread_exit.is_set() :
                break
            #TODO: for symbolic execution, use path group instead
            self._path = self._path.step()[0]
            #TODO: check for interrupts and serve
        self._thread_dead.set()

    def set_breakpoint(self, address, **properties):
        self._thread_can_run.clear()

        if address in AngrBreakpoint._defined_bkpts:
            log.debug("Breakpoint at " + str(address) + " already defined")
        else:
            #TODO: change this when implementing symbolic execution
            bkpt = self._path.state.inspect.b("instruction", when = simuvex.BP_BEFORE,
                                               instruction = address,
                                               action = AngrBreakpoint._on_angr_breakpoint_fire)
            AngrBreakpoint(self._system, bptk, address)
        self._thread_can_run.set()

    def delete_breakpoint(self, bkpt):
        bkpt.delete()

    def write_typed_memory(self, address, size, data):
        state = self._path.state
        value = state.se.BVV(data, size)
        state.memory.store(address, value)

    def read_typed_memory(self, address, size):
        state = self._path.state
        value = state.memory.load(address, size)
        if value.symbolic:
            log.debug("Symbolic value read at address: " + hex(address))
        return state.se.any_int(value) 

    def set_register(self, reg, val):
        state = self._path.state
        value = state.se.BVV(val)
        if !hasattr(state.regs, reg):
            raise Exception("Unknow register " + reg)
        value = state.se.BVV(val)
        state.memory.store(getattr(state.regs, reg), value)

    def get_register_from_nr(self, reg_nr):
        pass

    def get_register(self, reg):
        state = self._path.state
        if !hasattr(state.regs, reg):
            raise Exception("Unknow register " + reg)
        if getattr(state.regs, reg).symbolic:
            log.devug("Symbolic value read from register " + reg)
        return state.se.any_int(getattr(state.regs, reg))

