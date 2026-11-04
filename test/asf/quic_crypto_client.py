#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Line-oriented VCL client driven over stdin/stdout by test_quic_crypto.py.

Every operation is a JSON request on one line and a JSON reply on the next.
The module only binds the public vppcom.h ABI, so it can be run against the
libvppcom.so of any checkout under test.
"""

import ctypes as ct
import json
import socket
import sys
import time
from pathlib import Path

PROTO_QUIC = 4
APP_SCOPE_GLOBAL = 1
# vppcom_attr_op_t ordinal, counted from src/vcl/vppcom.h
ATTR_SET_CKPAIR = 35
# A certificate that ptls_load_certificate_chain() rejects while the private
# key loads, so the crypto context is built but no certificate chain is.
MALFORMED_CERT = b"-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n"
# Upper bound on how long connect() polls a non-blocking session before it
# closes the handle, so a stalled attempt cannot reach the VCL session-timeout.
CONNECT_POLL_LIMIT_S = 5.0
CONNECT_POLL_INTERVAL_S = 0.01


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

    def session(self):
        handle = self.call("session_create", PROTO_QUIC, 1)
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

    def connect(self):
        """Start a non-blocking connect and poll the session error for a bound."""
        handle = self.session()
        result = self.call("session_connect", handle, ct.byref(self.endpoint))
        errors = []
        polls = 0
        started = time.monotonic()
        while result != 0 and time.monotonic() - started < CONNECT_POLL_LIMIT_S:
            time.sleep(CONNECT_POLL_INTERVAL_S)
            polls += 1
            error = self.call("session_get_error", handle)
            if error != (errors[-1] if errors else None):
                errors.append(error)
            if error != 0:
                break
        waited = time.monotonic() - started
        if result == 0:
            self.connection = handle
        else:
            self.call("session_close", handle)
        return {
            "handle": handle,
            "connect": result,
            "errors": errors,
            "polls": polls,
            "waited_s": round(waited, 3),
        }

    def listen(self):
        self.listener = self.session()
        self.require_zero(
            self.call("session_bind", self.listener, ct.byref(self.endpoint)),
            "session_bind",
        )
        self.require_zero(
            self.call("session_listen", self.listener, 8), "session_listen"
        )
        return {"listener": self.listener}

    def accept(self):
        self.connection = self.call("session_accept", self.listener, None, 0)
        if self.connection < 0:
            raise RuntimeError(f"session_accept failed: {self.connection}")
        return {"accepted": self.connection}

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
            print(
                json.dumps({"id": request["id"], "result": operation(client, request)}),
                flush=True,
            )
    finally:
        client.destroy()


if __name__ == "__main__":
    main()
