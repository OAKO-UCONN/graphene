# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) Wojtek Porczyk <woju@invisiblethingslab.com>

import http.server
import itertools
import os
import pathlib
import socket

from cryptography.hazmat.backends import default_backend as _default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from . import _aesm_pb2 as aesm_pb2

ATTRIBUTES = bytes.fromhex('0600000000000000 1f00000000000000') # flags, xfrm
AESMD_SOCKET = pathlib.Path('/var/run/aesmd/aesm.socket')
SGX_DRIVER_PATHS = {
    'inkernel': pathlib.Path('/dev/sgx_enclave'),
    'dcap': pathlib.Path('/dev/sgx/enclave'),
    'oot': pathlib.Path('/dev/isgx'),
}

_backend = _default_backend()

fspath = getattr(os, 'fspath', str)  # pylint: disable=invalid-name

def get_token():
    mrenclave = os.urandom(256)
    key = rsa.generate_private_key(
        public_exponent=3, key_size=3072, backend=_backend)
    modulus = key.public_key().public_numbers().n.to_bytes(384, 'little')

    req = aesm_pb2.GetTokenReq(req=aesm_pb2.GetTokenReqRaw(
        signature=mrenclave,
        key=modulus,
        attributes=ATTRIBUTES,
        timeout=10000)).SerializeToString()

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(fspath(AESMD_SOCKET))
    sock.send(len(req).to_bytes(4, 'little'))
    sock.send(req)

    ret = aesm_pb2.GetTokenRet()
    ret_len = int.from_bytes(sock.recv(4), 'little')
    ret.ParseFromString(sock.recv(ret_len))

    return ret.ret.error

class Handler(http.server.BaseHTTPRequestHandler):
    @staticmethod
    def ex_driver():
        for driver, path in SGX_DRIVER_PATHS.items():
            state = path.is_char_device() and not path.is_symlink()
            yield 'sgx_driver{{type="{}"}} {}'.format(driver, int(state))

    @staticmethod
    def ex_aesmd():
        try:
            error = get_token()
            aesmd_serviceable = error == 0
            yield 'aesmd_up 1'
            yield 'aesmd_serviceable {}'.format(int(aesmd_serviceable))
            yield '#aesmd_error {}'.format(error)
        except FileNotFoundError:
            # connect() failed, not running
            yield 'aesmd_up 0'
            yield 'aesmd_serviceable 0'

    def do_GET(self):
        resp = ('\n'.join(itertools.chain(
            self.ex_driver(),
            self.ex_aesmd(),
        )) + '\n').encode('ascii')

        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-length', len(resp))
        self.end_headers()
        self.wfile.write(resp)

def main():
    http.server.HTTPServer(('', 9089), Handler).serve_forever()

if __name__ == '__main__':
    main()
