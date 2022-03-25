import anyio
import struct
import logging
import types
import os
import socket
from openssh.util import def_revconstant
from openssh import exception

from logging import debug


MUX_PROTOCOL_VERSION = 4

MUX_MSG_HELLO           = 0x00000001

MUX_C_NEW_SESSION       = 0x10000002
MUX_C_ALIVE_CHECK       = 0x10000004
MUX_C_TERMINATE         = 0x10000005
MUX_C_OPEN_FWD          = 0x10000006
MUX_C_CLOSE_FWD         = 0x10000007
MUX_C_NEW_STDIO_FWD     = 0x10000008
MUX_C_STOP_LISTENING    = 0x10000009
MUX_C_PROXY             = 0x1000000f

MUX_S_OK                = 0x80000001
MUX_S_PERMISSION_DENIED = 0x80000002
MUX_S_FAILURE           = 0x80000003
MUX_S_EXIT_MESSAGE      = 0x80000004
MUX_S_ALIVE             = 0x80000005
MUX_S_SESSION_OPENED    = 0x80000006
MUX_S_REMOTE_PORT       = 0x80000007
MUX_S_TTY_ALLOC_FAIL    = 0x80000008
MUX_S_PROXY             = 0x8000000f

MUX_FWD_LOCAL   = 1
MUX_FWD_REMOTE  = 2
MUX_FWD_DYNAMIC = 3

_revtype = def_revconstant(__name__, 'MUX_MSG_HELLO', 'MUX_[CS]_.*')
#_revfwd  = def_revconstant(__name__, 'MUX_FWD_.*')

def _pack_string(string, encoding):
    bytes = string.encode(encoding)
    return struct.pack(">I", len(bytes)) + bytes

def _pack_ui32_special(ui32):
    # sometimes negative numbers are used as magic number markers
    if ui32 < 0:
        return struct.pack(">i", i32)
    return struct.pack(">I", ui32)

def _pack_ui32(ui32):
    return struct.pack(">I", ui32)

_pack_bool = _pack_ui32
_zero_packed = _pack_ui32(0)
_empty_string_packed = _zero_packed

def _make_packet(packet_type, *fragments):
    l = 4
    for f in fragments:
        l += len(f)
    return b''.join([struct.pack(">II", l, packet_type), *fragments])

def _eat_ui32(buffer):
    (v,) = struct.unpack_from(">I", buffer)
    del buffer[0:4]
    return v

_eat_bool = _eat_ui32

def _eat_string(buffer, encoding):
    l = _eat_ui32(buffer)
    s = buffer[0:l].decode(encoding)
    del buffer[0:l]
    return s

def _peek_ui32(buffer, offset=0):
    return struct.unpack_from(">I", buffer, offset)

class Packet(types.SimpleNamespace):
    pass

class Mux:

    def __init__(self, ctl_path, encoding='utf-8', timeout=180):
        self._ctl_path = ctl_path
        self._socket = None
        self._encoding = encoding
        self._timeout = timeout
        self._last_request_id = 0
        self._session_id = None

    def _get_request_id(self):
        self._last_request_id += 1
        return self._last_request_id

    async def connect(self):
        self._socket = await anyio.connect_unix(self._ctl_path)
        await self._hello()

    async def send(self, packet):
        assert self._writer != None
        await self._writer.write(packet.get_bytes())

    def _make_packet_hello(self, **extensions):
        fragments = []
        for k, v in extensions.items():
            strings.append(_pack_string(k, self._encoding))
            strings.append(_pack_string(v, self._encoding))

        return _make_packet(MUX_MSG_HELLO,
                            _pack_ui32(MUX_PROTOCOL_VERSION),
                            *fragments)

    def _make_packet_new_session(self,
                                 request_id,
                                 want_tty_flag,
                                 want_X11_forwarding_flag,
                                 want_agent_flag,
                                 subsystem_flag,
                                 escape_char,
                                 terminal_type,
                                 command,
                                 environment_strings):
        return _make_packet(MUX_C_NEW_SESSION,
                            _pack_ui32(request_id),
                            _empty_string_packed, # reserved
                            _pack_bool(want_tty_flag),
                            _pack_bool(want_X11_forwarding_flag),
                            _pack_bool(want_agent_flag),
                            _pack_bool(subsystem_flag),
                            _pack_ui32(escape_char),
                            _pack_string(terminal_type, self._encoding),
                            _pack_string(command, self._encoding),
                            *[_pack_string(es, self._encoding) for es in environment_strings])

    def _make_packet_new_stdio_fwd(self,
                                   request_id,
                                   connect_host,
                                   connect_port):
        return _make_packet(MUX_C_NEW_STDIO_FWD,
                            _pack_ui32(request_id),
                            _empty_string_packed,
                            _pack_string(connection_host, self._encoding),
                            _pack_string(connect_port, self._encoding))

    def _make_packet_alive_check(self, request_id):
        return _make_packet(MUX_C_ALIVE_CHECK,
                            _pack_ui32(request_id))

    def _make_packet_terminate(self, request_id):
        return _make_packet(MUX_C_TERMINATE,
                            _pack_ui32(request_id))

    def _make_packet_any_fwd(self,
                             mux_open_or_close_cmd,
                             request_id,
                             forwarding_type,
                             listen_host,
                             listen_port,
                             connect_host,
                             connect_port):
        return _make_packet(mux_open_or_close_cmd,
                            _pack_ui32(request_id),
                            _pack_ui32(forwarding_type),
                            _pack_string(listen_host, self._encoding),
                            _pack_ui32_special(listen_port),
                            _pack_string(connect_host, self._encoding),
                            _pack_ui32_special(connect_port))

    def _make_packet_open_fwd(self, *args):
        return self._make_packet_any_fwd(MUX_C_OPEN_FWD, *args)

    def _make_packet_close_fwd(self, *args):
        return self._make_packet_any_fwd(MUX_C_CLOSE_FWD, *args)

    def _make_packet_stop_listening(self, request_id):
        return _make_packet(MUX_C_STOP_LISTENING,
                            _pack_ui32(request_id))

    def _make_packet_proxy(self, request_id):
        return _make_packet(MUX_C_PROXY,
                            _pack_ui32(request_id))

    def _set_timeout(self):
        return anyio.fail_after(self._timeout)

    async def _send_packet(self, buffer):
        debug("sending packet, len: %d", len(buffer))
        try:
            with self._set_timeout():
                await self._socket.send(buffer)
        except anyio.EndOfStream as ex:
            raise exception.SSHMuxClosedException("Mux socket closed unexpectedly") from ex
        except TimeoutError as ex:
            raise exception.SSHMuxTimeoutException("Timeout while sending packet over mux socket") from ex

    async def _send_fd(self, fd):
        with self._set_timeout():
            await self._socket.send_fds(b'\x00', [fd])

    async def _receive_exactly(self, count, with_initial_timeout=True):
        chunks = []
        if count > 0 and not with_initial_timeout:
            chunk = await self._socket.receive(count)
            count -= len(chunk)
            chunks.append(chunk)
        while count > 0:
            with self._set_timeout():
                chunk = await self._socket.receive(count)
                count -= len(chunk)
                chunks.append(chunk)
        return bytearray(b'').join(chunks)

    async def _read_packet(self, with_initial_timeout=True):
        buffer = await self._receive_exactly(4, with_initial_timeout)
        size = _eat_ui32(buffer)
        assert size < 40000
        debug("waiting for packet of size %d", size)
        return await self._receive_exactly(size)

    def _eat_packet(self, buffer):
        packet_type = _eat_ui32(buffer)
        packet = Packet(type=packet_type, type_name=_revtype(packet_type))
        debug("packet of type %s[0x%x] received", packet.type_name, packet_type)
        if packet_type == MUX_MSG_HELLO:
            packet.protocol_version = _eat_ui32(buffer)
            packet.extensions = {}
            while len(buffer) > 0:
                k = _eat_string(buffer, self._encoding)
                v = _eat_string(buffer, self._encoding)
                packet.extensions[k] = v
        elif packet_type in (MUX_S_TTY_ALLOC_FAIL, MUX_S_EXIT_MESSAGE):
                packet.session_id = _eat_ui32(buffer)
                if packet_type == MUX_S_EXIT_MESSAGE:
                    packet.exit_value = _eat_ui32(buffer)
        else:
            packet.request_id = _eat_ui32(buffer)
            if packet_type in (MUX_S_PROXY, MUX_S_OK):
                pass
            elif packet_type in (MUX_S_PERMISSION_DENIED, MUX_S_FAILURE):
                packet.reason = _eat_string(buffer, self._encoding)
            elif packet_type == MUX_S_EXIT_MESSAGE:
                packet.exit_value = _eat_ui32(buffer)
            elif packet_type == MUX_S_ALIVE:
                packet.server_pid = _eat_ui32(buffer)
            elif packet_type == MUX_S_SESSION_OPENED:
                packet.session_id = _eat_ui32(buffer)
            elif packet_type == MUX_S_REMOTE_PORT:
                packet.remote_listen_port = _eat_ui32(buffer)
            else:
                raise Exception("Unknown mux packet type %s[0x%d], request_id: %d" % (packet.type_name, packet_type, packet.request_id))

        debug("packet unpacked: %s", packet)
        return packet

    async def _wait_for_packet(self, with_initial_timeout=True):
        buffer = await self._read_packet(with_initial_timeout)
        debug("packet read: %s", buffer)
        packet = self._eat_packet(buffer)
        assert len(buffer) == 0
        return packet

    async def _wait_for_response(self, expected_type, with_initial_timeout=False):
        try:
            packet = await self._wait_for_packet(with_initial_timeout=with_initial_timeout)
        except anyio.EndOfStream as ex:
            raise exception.SSHMuxClosedException("Mux socket closed unexpectedly") from ex
        except TimeoutError as ex:
            raise exception.SSHMuxTimeoutException("Timeout while reading packet from mux socket") from ex

        if packet.type in (MUX_S_ALIVE, MUX_S_OK, MUX_S_PERMISSION_DENIED, MUX_S_FAILURE, MUX_S_SESSION_OPENED, MUX_S_REMOTE_PORT):
            if packet.request_id != self._last_request_id:
                exception.SSHMuxProtocolException("Received (%d) and expected (%d) request ids do not match, packet type: %s[0x%x]" %
                                                  (packet.request_id, self._last_request_id, packet.type_name, packet.type))
        if packet.type in (MUX_S_EXIT_MESSAGE, MUX_S_TTY_ALLOC_FAIL):
            if packet.session_id != self._session_id:
                exception.SSHMuxProtocolException("Received (%d) and expected (%d) session ids do not match, packet type: %s[0x%x]" %
                                                  (packet.session_id, self._session_id, packet.type_name, packet.type))
        if expected_type == packet.type:
            return packet

        if packet.type == MUX_S_FAILURE:
            raise exception.SSHFailureException(packet.reason)
        if packet.type == MUX_S_PERMISSION_DENIED:
            raise exception.SSHPermissionDeniedException(packet.reason)
        raise exception.SSHMuxProtocolException("Bad message %s[0x%x] received, expected %s[0x%x]" %
                                                (packet.type_name, packet.type, _revtype(expected_type), expected_type))

    async def _hello(self):
        await self._send_packet(self._make_packet_hello())
        packet = await self._wait_for_response(MUX_MSG_HELLO)
        assert packet.protocol_version == MUX_PROTOCOL_VERSION
        self.server_protocol_extensions = packet.extensions

    async def _new_session(self,
                           cmd_line,
                           want_tty=False,
                           want_X11=False,
                           want_agent=False,
                           subsystem=False,
                           escape_char=0xffffffff,
                           terminal_type=None,
                           environment_strings=[]):

        if terminal_type is None:
            terminal_type = os.environ.get('TERM', 'vt100')

        buffer = self._make_packet_new_session(self._get_request_id(),
                                               want_tty,
                                               want_X11,
                                               want_agent,
                                               subsystem,
                                               escape_char,
                                               terminal_type,
                                               cmd_line,
                                               environment_strings)
        await self._send_packet(buffer)
        # this is blocking!
        await self._send_fd(1)
        await self._send_fd(2)
        await self._send_fd(3)

        res = await self._wait_for_response(MUX_S_SESSION_OPENED)
        self._session_id = res.session_id
        return True

    async def _wait_for_process(self):
        assert self._session_id is not None
        res = await self._wait_for_response(MUX_S_EXIT_MESSAGE, with_initial_timeout=False)
        self._exit_value = res.exit_value
        return res.exit_value

    async def _alive_check(self):
        await self._send_packet(self._make_packet_alive_check(self._get_request_id()))
        await self._wait_for_response(MUX_S_ALIVE)
        return True
