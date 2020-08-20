# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2020 Paweł Marczewski <pawel@invisiblethingslab.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, see <https://www.gnu.org/licenses/>.


'''
A client and server for socket-based QubesRPC (currently used for
qrexec-policy-agent).

Currently disregards the target specification part of the request.
'''

import os
import os.path
import asyncio

from . import RPC_PATH
from .client import call_async

class SocketService:
    def __init__(self, socket_path):
        self._socket_path = socket_path

    async def run(self):
        server = await self.start()
        async with server:
            await server.serve_forever()

    async def start(self):
        if os.path.exists(self._socket_path):
            os.unlink(self._socket_path)
        return await asyncio.start_unix_server(self._client_connected,
                                               path=self._socket_path)

    async def _client_connected(self, reader, writer):
        try:
            data = await reader.read()
            assert b'\0' in data, data
            header, payload = data.split(b'\0', 1)

            # Note that we process only the first two parts (service and
            # source_domain) and disregard the second two parts (target
            # specification) that appear when we're running in dom0.
            header_parts = header.decode('ascii').split(' ')
            assert len(header_parts) >= 2, header
            service = header_parts[0]
            source_domain = header_parts[1]

            response = await self.handle_request(payload, service, source_domain)

            writer.write(response)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_request(
            self,
            payload: bytes,
            service: str,
            source_domain: str) -> bytes:
        raise NotImplementedError()


def call_socket_service(
        remote_domain, service, source_domain, payload: bytes,
        rpc_path=RPC_PATH) -> bytes:
    '''
    Call a socket service, either over qrexec or locally.
    '''

    if remote_domain == source_domain:
        return call_socket_service_local(
            service, source_domain, payload, rpc_path)
    return call_socket_service_remote(
        remote_domain, service, payload)


async def call_socket_service_local(service, source_domain, payload: bytes,
                                    rpc_path=RPC_PATH) -> bytes:
    if source_domain == 'dom0':
        header = '{} dom0 name dom0\0'.format(service).encode('ascii')
    else:
        header = '{} {}\0'.format(service, source_domain).encode('ascii')

    path = os.path.join(rpc_path, service)
    reader, writer = await asyncio.open_unix_connection(path)
    writer.write(header)
    writer.write(payload)
    writer.write_eof()
    await writer.drain()
    response = await reader.read()
    return response


async def call_socket_service_remote(
        remote_domain, service, payload: bytes) -> bytes:
    output_data = await call_async(remote_domain, service, input=payload)
    return output_data
