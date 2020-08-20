#
# The Qubes OS Project, https://www.qubes-os.org/
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
#

'''
A qrexec socket service that allows viewing and editing the policy content.
'''

import argparse
import asyncio
import logging
import logging.handlers
from typing import Optional
from pathlib import Path

from .. import POLICYPATH, POLICY_ADMIN_SOCKET_PATH
from ..server import SocketService


class PolicyAdmin(SocketService):
    '''
    A policy-admin server.

    The responses have the same format as qubesd:

    * success: ``30 <response>``
    * error: ``32 <error class> 00 ( <traceback> )? 00 <description> 00``
    '''

    def __init__(self, socket_path, policy_path, log):
        super().__init__(socket_path)
        self.api = PolicyApi(policy_path)
        self.log = log

    async def handle_request(self, payload: bytes, service, source_domain):
        if '+' in service:
            service_name, arg = service.split('+', 1)
        else:
            service_name, arg = service, ''

        try:
            response = self.api.handle_request(payload, service_name, arg)
        except PolicyApiException as exc:
            self.log.exception('%s (%s): error response',
                             service, source_domain)
            return (b'\x32' + type(exc).__name__.encode('utf-8') + b'\0'
                    + b'\0'
                    + str(exc).encode('utf-8') + b'\0')
        except Exception:  # pylint: disable=broad-except
            self.log.exception('%s (%s): error while handling',
                             service, source_domain)
            return b''
        else:
            self.log.info('%s (%s)', service, source_domain)
            if response is not None:
                return b'\x30' + response
            return b'\x30'


class PolicyApiException(Exception):
    '''
    An exception with message to the user.
    '''


def method(service_name, no_payload=False, no_arg=False):
    def decorator(func):
        func.api_service_name = service_name
        func.api_no_payload = no_payload
        func.api_no_arg = no_arg
        return func
    return decorator


class PolicyApi:
    def __init__(self, policy_path):
        self.policy_path = policy_path

    def handle_request(self, payload: bytes, service_name: str, arg: str) \
        -> Optional[bytes]:

        func = self.find_method(service_name)
        if not func:
            raise PolicyApiException(
                'unrecognized method: {}'.format(service_name))

        args = []
        if func.api_no_payload:
            if payload != b'':
                raise PolicyApiException('unexpected payload')
        else:
            args.append(payload)

        if func.api_no_arg:
            if arg != '':
                raise PolicyApiException('unexpected argument')
        else:
            args.append(arg)

        return func(*args)

    def find_method(self, service_name):
        for attr in dir(self):
            func = getattr(self, attr)
            if callable(func) and hasattr(func, 'api_service_name'):
                if func.api_service_name == service_name:
                    return func

        return None

    @method('policy.List', no_payload=True, no_arg=True)
    def policy_list(self):
        names = []
        for file_path in self.policy_path.iterdir():
            if file_path.name.endswith('.policy'):
                names.append(file_path.name[:-len('.policy')])

        names.sort()
        return ''.join(name + '\n' for name in names).encode('ascii')

    @method('policy.Get', no_payload=True)
    def policy_get(self, arg):
        file_path = self.policy_path / (arg + '.policy')
        assert file_path.parent == self.policy_path

        if not file_path.is_file():
            raise PolicyApiException('Not found: {}'.format(file_path))

        return file_path.read_bytes()


parser = argparse.ArgumentParser()

parser.add_argument(
    '-s', '--socket-path', metavar='DIR', type=str,
    default=POLICY_ADMIN_SOCKET_PATH,
    help='path to socket')

parser.add_argument(
    '--policy-path', metavar='DIR', type=str,
    default=POLICYPATH,
    help='path to policy directory')


def main():
    args = parser.parse_args()

    log = logging.getLogger('policy-admin')
    log.setLevel(logging.INFO)
    if not log.handlers:
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        log.addHandler(handler)

    agent = PolicyAdmin(
        args.socket_path, Path(args.policy_path), log)

    loop = asyncio.get_event_loop()
    tasks = [
        agent.run(),
    ]
    loop.run_until_complete(asyncio.wait(tasks))


if __name__ == '__main__':
    main()
