import os
import subprocess
import random
import pathlib
import anyio
import anyio.lowlevel
import time
import logging
import socket
from logging import debug

from subprocess import PIPE, STDOUT, DEVNULL


from openssh import state
from openssh import error
from openssh import mux

class SSH:

    def __init__(self,
                 host,
                 master_opts = []):
        self._host = host
        self._master_opts = master_opts
        self._ctl_path = pathlib.Path(f"/tmp/ssh_mux_socket_{random.randrange(0, 100000)}")
        self._master_state = state.NEW
        self._error = error.OK
        self._error_string = "Ok"
        self._master_start_time = None
        self._timeout = 240

    async def connect(self):
        return await self._wait_for_master()

    def ctl_path(self):
        # TODO
        return self._ctl_path

    def _set_error(self, error, string=None):
        self._error = error
        self._error_string = string

    async def _start_master(self):
        ctl_path = self.ctl_path()
        cmd = ["ssh",
               *self._master_opts,
               "-2MN",
               "-oControlPersist=no",
               "-oBatchMode=yes",
               f"-S{ctl_path}",
               self._host,
               "--"]
        self._master_process = subprocess.Popen(cmd)

        self._master_state = state.AWAITING_MUX
        self._master_start_time = time.time()

    async def _wait_for_master(self):
        while True:
            if self._master_state == state.RUNNING:
                return True

            if self._master_state == state.GONE:
                return False

            if self._master_state == state.NEW:
                await self._start_master()

            if self._master_state == state.KILLING:
                # TODO
                self._master_state == state.GONE

            if self._master_state == state.LOGIN:
                # TODO
                self._set_error(error.MASTER_FAILED, "Password login not implemented yet")
                self._master_state = state.KILLING
                continue

            if self._master_state == state.AWAITING_MUX:
                ctl_path = self.ctl_path()
                if ctl_path.exists():
                    if ctl_path.is_socket():
                        self._master_state = state.RUNNING
                        continue
                    else:
                        self._master_state = state.KILLING
                        self._set_error(error.MASTER_FAILED,
                                        f"Bad file object at {ctl_path}")
                else:
                    await anyio.sleep(0.05)

            if time.time() - self._master_start_time > self._timeout:
                self._set_error(error.MASTER_FAILED, "Timeout while waiting for master connection")
                self._master_state = state.KILLING
                continue


    async def run(self, cmd):
        m = mux.Mux(self.ctl_path())
        await m.connect()
        #if (await m._new_session("cat /etc/passwd")):
        #    debug("command started")
        #    code = await m._wait_for_process()
        #    debug("command exited with code %d", code)

        await m._new_session("echo hello world!") # "cat /etc/passwd")
        await m._alive_check()

        code = await m._wait_for_process()
        code = await m._wait_for_process()

    async def open_ex(self,
                      command,
                      input = None,
                      stdin = None, stdout = None, stderr = None,
                      check = True, env = None):

        m = mux.Mux(self.ctl_path())
        await m.connect()

        stdin_my_pipe = None
        stdout_my_pipe = None
        stderr_my_pipe = None

        stdin_child_fd = None
        stdout_child_fd = None
        stderr_child_fd = None

        close_me_later = []

        #if stdin is None:
        #    stdin_child_fd = 0
        #elif type(stdin) is int:
        #    if stdin >= 0:
        #        stdin_child_fd = stdin
        #    elif stdin == DEVNULL:
        #        devnull = open(os.devnull, "w")
        #        stdin_child_fd = devnull.fileno()
        #        close_me_later.append(devnull)
        #    else stdin == PIPE:

        (s1, s2) = socket.socketpair()

        print(anyio.lowlevel.get_asynclib())

            

