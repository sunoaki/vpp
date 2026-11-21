#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Line-oriented VCL client driven over stdin/stdout by test_quic_crypto.py.

Every operation is a JSON request on one line and a JSON reply on the next.
The module only binds the public vppcom.h ABI, so it can be run against the
libvppcom.so of any checkout under test.
"""

import ctypes as ct
import errno
import json
import socket
import sys
import time
from pathlib import Path

PROTO_QUIC = 4
APP_SCOPE_GLOBAL = 1
# vppcom_attr_op_t ordinals, counted from src/vcl/vppcom.h
ATTR_GET_NWRITE = 1
ATTR_SET_CKPAIR = 35
# vppcom_session_connect returns this for every non-blocking session, whatever
# the outcome; the outcome arrives later as a session error or as writeability.
VPPCOM_EINPROGRESS = -115
# vppcom_session_accept returns VPPCOM_EAGAIN for a non-blocking listener as
# soon as the app event queue holds no accept event. vppcom.h defines it as
# -EAGAIN, so take the value from errno rather than hardcoding it.
VPPCOM_EAGAIN = -errno.EAGAIN
# A certificate that ptls_load_certificate_chain() rejects while the private
# key loads, so the crypto context is built but no certificate chain is.
MALFORMED_CERT = b"-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n"
# Upper bound on how long connect() polls a non-blocking session before it
# closes the handle, so a stalled attempt cannot reach the VCL session-timeout.
CONNECT_POLL_LIMIT_S = 5.0
CONNECT_POLL_INTERVAL_S = 0.01
# Upper bound on how long accept() waits for an accept event. The listener is
# non-blocking, and vppcom_session_accept on a non-blocking listener returns
# VPPCOM_EAGAIN instead of waiting, so this bound is what keeps a handshake
# that never completes from blocking the helper inside the C call.
ACCEPT_POLL_LIMIT_S = 5.0


class Endpoint(ct.Structure):
    """vppcom_endpt_t from src/vcl/vppcom.h."""

    _fields_ = [
        ("unused", ct.c_uint8),
        ("is_ip4", ct.c_uint8),
        ("ip", ct.POINTER(ct.c_uint8)),
        ("port", ct.c_uint16),
        ("unused2", ct.c_uint64),
        ("app_tlv_len", ct.c_uint32),
        ("app_tlvs", ct.c_void_p),
    ]


class CertKeyPair(ct.Structure):
    """vppcom_cert_key_pair_t from src/vcl/vppcom.h."""

    _fields_ = [
        ("cert", ct.c_char_p),
        ("key", ct.c_char_p),
        ("cert_len", ct.c_uint32),
        ("key_len", ct.c_uint32),
    ]


SIGNATURES = {
    "app_create": ([ct.c_char_p], ct.c_int),
    "app_destroy": ([], None),
    "add_cert_key_pair": ([ct.POINTER(CertKeyPair)], ct.c_int),
    "del_cert_key_pair": ([ct.c_uint32], ct.c_int),
    "session_create": ([ct.c_uint8, ct.c_uint8], ct.c_int),
    "session_attr": (
        [ct.c_uint32, ct.c_uint32, ct.c_void_p, ct.POINTER(ct.c_uint32)],
        ct.c_int,
    ),
    "session_connect": ([ct.c_uint32, ct.POINTER(Endpoint)], ct.c_int),
    "session_bind": ([ct.c_uint32, ct.POINTER(Endpoint)], ct.c_int),
    "session_listen": ([ct.c_uint32, ct.c_uint32], ct.c_int),
    "session_accept": ([ct.c_uint32, ct.POINTER(Endpoint), ct.c_uint32], ct.c_int),
    "session_close": ([ct.c_uint32], ct.c_int),
    "session_get_error": ([ct.c_uint32], ct.c_int),
    "session_index": ([ct.c_uint32], ct.c_int),
    "select": (
        [
            ct.c_int,
            ct.POINTER(ct.c_ulong),
            ct.POINTER(ct.c_ulong),
            ct.POINTER(ct.c_ulong),
            ct.c_double,
        ],
        ct.c_int,
    ),
}


class Client:
    def __init__(self, library, address, port):
        self.lib = ct.CDLL(library)
        for name, (args, result) in SIGNATURES.items():
            function = getattr(self.lib, "vppcom_" + name)
            function.argtypes = args
            function.restype = result
        self.ip = (ct.c_uint8 * 4).from_buffer_copy(socket.inet_aton(address))
        self.endpoint = Endpoint(is_ip4=1, ip=self.ip, port=socket.htons(port))
        self.keep = []
        self.pair = None
        self.attached = False
        self.connection = None
        self.listener = None

    def call(self, name, *args):
        return getattr(self.lib, "vppcom_" + name)(*args)

    @staticmethod
    def require_zero(result, operation):
        if result != 0:
            raise RuntimeError(f"{operation} failed: {result}")
        return result

    def attach(self, cert, key):
        self.require_zero(
            self.call("app_create", b"quic-credential-regression"), "app_create"
        )
        self.attached = True
        cert_bytes = MALFORMED_CERT if cert == "malformed" else Path(cert).read_bytes()
        key_bytes = Path(key).read_bytes()
        pair = CertKeyPair(cert_bytes, key_bytes, len(cert_bytes), len(key_bytes))
        self.keep.append(pair)
        self.pair = self.call("add_cert_key_pair", ct.byref(pair))
        if self.pair < 0:
            raise RuntimeError(f"add_cert_key_pair failed: {self.pair}")
        return {
            "app_create": 0,
            "pair": self.pair,
            "cert_len": len(cert_bytes),
            "key_len": len(key_bytes),
        }

    def session(self, is_nonblocking=1):
        handle = self.call("session_create", PROTO_QUIC, is_nonblocking)
        if handle < 0:
            raise RuntimeError(f"session_create failed: {handle}")
        index = ct.c_uint32(self.pair)
        length = ct.c_uint32(ct.sizeof(ct.c_uint32))
        self.require_zero(
            self.call(
                "session_attr",
                handle,
                ATTR_SET_CKPAIR,
                ct.byref(index),
                ct.byref(length),
            ),
            "session_attr SET_CKPAIR",
        )
        return handle

    def write_ready(self, handle):
        """Return the available write count, or a negative VCL error.

        vppcom_session_attr returns the count itself for GET_NWRITE and does
        not touch the buffer, so there is nothing to assert: a negative return
        is EBADFD/ECONNRESET/ENOTCONN and the caller treats it as not ready.
        """
        return self.call("session_attr", handle, ATTR_GET_NWRITE, None, None)

    def wait_writable(self, handle, timeout):
        """Wait until the session is writable, draining the app event queue.

        vppcom_select is the primitive that drains it: the CONNECTED event is
        handled there, which is what moves the session to VCL_STATE_READY and
        stores any vpp_error. Reading session_get_error or GET_NWRITE without
        it only sees the state frozen at connect() time.
        """
        index = self.call("session_index", handle)
        n_bits = index + 1
        words = (n_bits + 63) // 64
        read_map = (ct.c_ulong * words)()
        write_map = (ct.c_ulong * words)()
        write_map[index // 64] = 1 << (index % 64)
        return self.call("select", n_bits, read_map, write_map, None, float(timeout))

    def connect(self):
        """Start a non-blocking connect and wait for it to settle.

        vppcom_session_connect returns VPPCOM_EINPROGRESS for a non-blocking
        session whether or not the connect will succeed, so the outcome is
        observed instead: writability means the session reached
        VCL_STATE_READY, a non-zero session error means it failed, and neither
        before the poll limit means the attempt stalled.
        """
        handle = self.session()
        queued = self.call("session_connect", handle, ct.byref(self.endpoint))
        if queued != VPPCOM_EINPROGRESS:
            raise RuntimeError(
                f"session_connect on a non-blocking session returned {queued}"
            )
        errors = []
        polls = 0
        ready = False
        started = time.monotonic()
        while time.monotonic() - started < CONNECT_POLL_LIMIT_S:
            remaining = CONNECT_POLL_LIMIT_S - (time.monotonic() - started)
            polls += 1
            self.wait_writable(handle, min(remaining, CONNECT_POLL_INTERVAL_S))
            error = self.call("session_get_error", handle)
            if error != (errors[-1] if errors else None):
                errors.append(error)
            if error:
                break
            ready = self.write_ready(handle) > 0
            if ready:
                break
        waited = time.monotonic() - started
        if ready:
            self.connection = handle
        else:
            self.call("session_close", handle)
        return {
            "handle": handle,
            "connect": queued,
            "connected": ready,
            "errors": errors,
            "polls": polls,
            "waited_s": round(waited, 3),
        }

    def listen(self):
        # The listener must be non-blocking: vppcom_session_accept waits on the
        # worker message queue without a timeout (src/vcl/vppcom.c, the
        # vcl_worker_wait_mq(wrk, -1, ...) loop) for a blocking listener, so a
        # handshake that never completes would block the helper inside the C
        # call and no later operation, close or app_destroy could run. A
        # non-blocking listener returns VPPCOM_EAGAIN instead, and accept()
        # bounds the wait with vppcom_select.
        self.listener = self.session(is_nonblocking=1)
        self.require_zero(
            self.call("session_bind", self.listener, ct.byref(self.endpoint)),
            "session_bind",
        )
        self.require_zero(
            self.call("session_listen", self.listener, 8), "session_listen"
        )
        return {"listener": self.listener}

    def wait_readable(self, handle, timeout):
        """Wait until the session is readable, draining the app event queue.

        For a listener, readability means its accept_evts_fifo has an entry, so
        this is what turns the accept wait into a bounded one.
        """
        index = self.call("session_index", handle)
        n_bits = index + 1
        words = (n_bits + 63) // 64
        read_map = (ct.c_ulong * words)()
        read_map[index // 64] = 1 << (index % 64)
        return self.call("select", n_bits, read_map, None, None, float(timeout))

    def accept(self):
        """Accept one connection, waiting at most ACCEPT_POLL_LIMIT_S for it.

        vppcom_session_accept on a non-blocking listener returns VPPCOM_EAGAIN
        rather than waiting, so the wait belongs here: poll the listener's
        readability and only call accept once an accept event is queued. A
        handshake that never completes is then reported as a timeout with the
        seconds waited instead of blocking the helper.
        """
        started = time.monotonic()
        polls = 0
        while True:
            remaining = ACCEPT_POLL_LIMIT_S - (time.monotonic() - started)
            if remaining <= 0:
                raise RuntimeError(
                    f"session_accept saw no connection within "
                    f"{ACCEPT_POLL_LIMIT_S}s on listener {self.listener} "
                    f"after {polls} polls"
                )
            polls += 1
            self.wait_readable(self.listener, min(remaining, CONNECT_POLL_INTERVAL_S))
            handle = self.call("session_accept", self.listener, None, 0)
            if handle == VPPCOM_EAGAIN:
                continue
            if handle < 0:
                raise RuntimeError(f"session_accept failed: {handle}")
            self.connection = handle
            break
        return {
            "accepted": self.connection,
            "polls": polls,
            "waited_s": round(time.monotonic() - started, 3),
        }

    def close(self):
        reply = {}
        for name in ("connection", "listener"):
            handle = getattr(self, name)
            if handle is not None:
                reply[name] = self.call("session_close", handle)
                setattr(self, name, None)
        return reply

    def destroy(self):
        if self.attached:
            self.call("app_destroy")
            self.attached = False
        self.pair = None
        return {"app_destroy": True}

    def detach(self):
        result = {}
        if self.pair is not None:
            result["del_cert_key_pair"] = self.call("del_cert_key_pair", self.pair)
            self.require_zero(result["del_cert_key_pair"], "del_cert_key_pair")
            self.pair = None
        result.update(self.destroy())
        return result


OPERATIONS = {
    "attach": lambda client, request: client.attach(request["cert"], request["key"]),
    "connect": lambda client, request: client.connect(),
    "listen": lambda client, request: client.listen(),
    "accept": lambda client, request: client.accept(),
    "close": lambda client, request: client.close(),
    "detach": lambda client, request: client.detach(),
    "destroy": lambda client, request: client.destroy(),
}


def main():
    library, address, port = sys.argv[1:]
    client = Client(library, address, int(port))
    try:
        for line in sys.stdin:
            request = json.loads(line)
            operation = OPERATIONS.get(request["operation"])
            if operation is None:
                raise ValueError(f"unknown operation {request['operation']}")
            # Report a failed operation as a reply rather than letting it end
            # the process: an exception here would skip the remaining requests,
            # so the test would also report a helper that exited early and the
            # original failure would be buried under a cleanup failure.
            try:
                reply = {"result": operation(client, request)}
            except Exception as error:
                print(
                    json.dumps(
                        {
                            "id": request["id"],
                            "error": f"{type(error).__name__}: {error}",
                        }
                    ),
                    flush=True,
                )
                break
            print(json.dumps(dict(reply, id=request["id"])), flush=True)
    finally:
        client.destroy()


if __name__ == "__main__":
    main()
