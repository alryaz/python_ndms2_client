import asyncio
import json
import logging
import re
import shlex
import urllib
import warnings
from hashlib import sha256, md5
from pprint import pprint
from typing import Dict, List, Tuple, Union, NamedTuple, Optional, Mapping, Any, Iterable
from urllib.parse import urljoin

import aiohttp

from ndms2_client.connection import Connection, TelnetConnection, ConnectionException, \
    InvalidCommandException, AuthenticationException, InvalidDataException, DataNotFoundException
from ndms2_client.utils import rget

_LOGGER = logging.getLogger(__name__)


_VERSION_CMD = 'show version'
_ARP_CMD = 'show ip arp'
_ASSOCIATIONS_CMD = 'show associations'
_HOTSPOT_CMD = 'show ip hotspot'
_INTERFACE_CMD = 'show interface %s'
_INTERFACES_CMD = 'show interface'
_ARP_REGEX = re.compile(
    r'(?P<name>.*?)\s+' +
    r'(?P<ip>([0-9]{1,3}[.]){3}[0-9]{1,3})?\s+' +
    r'(?P<mac>(([0-9a-f]{2}[:-]){5}([0-9a-f]{2})))\s+' +
    r'(?P<interface>([^ ]+))\s+'
)


class Device(NamedTuple):
    mac: str
    name: str
    ip: str
    interface: str

    @classmethod
    def from_dict(cls, info: Mapping) -> "Device":
        return cls(
            mac=str(info.get('mac', info.get('via')).upper()),
            name=str(info.get('name', info.get('hostname', 'unknown'))),
            ip=str(info.get('ip')),
            interface=str(rget(info, 'interface', 'id', default=info.get('ap')))
        )


class RouterInfo(NamedTuple):
    name: str
    fw_version: str
    fw_channel: str
    model: str
    hw_version: str
    manufacturer: str
    vendor: str
    region: str

    @classmethod
    def from_dict(cls, info: Mapping) -> "RouterInfo":
        return cls(
            name=str(info.get('description', info.get('model', 'NDMS2 Router'))),
            fw_version=str(info.get('title', info.get('release'))),
            fw_channel=str(info.get('sandbox', 'unknown')),
            model=str(info.get('model', info.get('hw_id'))),
            hw_version=str(info.get('hw_version', 'N/A')),
            manufacturer=str(info.get('manufacturer')),
            vendor=str(info.get('vendor')),
            region=str(info.get('region', 'N/A')),
        )


class InterfaceInfo(NamedTuple):
    name: str
    type: Optional[str]
    description: Optional[str]
    link: Optional[str]
    connected: Optional[str]
    state: Optional[str]
    mtu: Optional[int]
    address: Optional[str]
    mask: Optional[str]
    uptime: Optional[int]
    security_level: Optional[str]
    mac: Optional[str]

    @classmethod
    def from_dict(cls, info: Mapping) -> "InterfaceInfo":
        if 'id' not in info:
            raise ValueError('source dictionary must contain an identifier')
        return cls(
            name=_str(info.get('interface-name')) or str(info['id']),
            type=_str(info.get('type')),
            description=_str(info.get('description')),
            link=_str(info.get('link')),
            connected=_str(info.get('connected')),
            state=_str(info.get('state')),
            mtu=_int(info.get('mtu')),
            address=_str(info.get('address')),
            mask=_str(info.get('mask')),
            uptime=_int(info.get('uptime')),
            security_level=_str(info.get('security-level')),
            mac=str(info['mac']).upper() if info.get('mac') else None,
        )


CommandArgumentType = Union[int, float, str, bytes, bytearray, Iterable['CommandArgumentType']]
RCIPostType = Mapping[str, Union[Iterable[Union[str, int, float]], 'RCIPostType']]


class ConsoleCommand:
    def __init__(self, argument: CommandArgumentType, *args: CommandArgumentType):
        if argument is None or None in args:
            raise ValueError('command cannot contain arguments of `None` value')
        if len(args) == 0 and isinstance(argument, (str, bytes, bytearray)):
            self.arguments = shlex.split(argument)
        else:
            self.arguments = list([argument, *args])

    def __str__(self):
        return '\n'.join(self.to_cli(multiple=True))

    def __repr__(self):
        return f'<{self.__class__.__name__}:{self.arguments}>'

    @classmethod
    def expand_arguments(cls, arguments: Iterable[CommandArgumentType], multiline: bool = True) -> Union[List[List[str]], List[str]]:
        """Dogs"""
        current_command = []
        for i, argument in enumerate(arguments):
            if isinstance(argument, (int, float, str)):
                current_command.append(str(argument))
            elif isinstance(argument, (bytes, bytearray)):
                current_command.append(argument.decode('utf-8'))
            elif multiline:
                next_commands = cls.expand_arguments(arguments[i+1:], multiline=True)
                return [
                    [
                        *current_command,
                        sub_value,
                        *next_command
                    ]
                    for sub_value in cls.expand_arguments(argument, multiline=False)
                    for next_command in next_commands
                ]
            else:
                raise ValueError('multiline arguments encountered')

        if multiline:
            return [current_command]
        return current_command

    @staticmethod
    def arguments_are_multiline(arguments: List[CommandArgumentType]):
        return any(map(lambda x: not isinstance(x, (int, float, str, bytes, bytearray)), arguments))

    def is_multiline(self):
        return self.arguments_are_multiline(self.arguments)

    def expanded(self, multiple: bool = True):
        """Cats"""
        return self.expand_arguments(self.arguments, multiline=multiple)

    @staticmethod
    def compile_cli_command(arguments: List[str]) -> str:
        return ' '.join(map(shlex.quote, arguments))

    def to_cli(self, multiple: bool = False) -> Union[str, List[str]]:
        expanded = self.expanded(multiple=multiple)
        if multiple:
            return list(map(ConsoleCommand.compile_cli_command, expanded))
        return ConsoleCommand.compile_cli_command(expanded)

    @staticmethod
    def compile_rci_path(arguments: List[Any]) -> str:
        return '/'.join(map(urllib.parse.quote, map(str, arguments)))

    def to_rci_path(self, multiple: bool = False) -> Union[str, List[str]]:
        expanded = self.expanded(multiple=multiple)
        if multiple:
            return list(map(ConsoleCommand.compile_rci_path, expanded))
        return ConsoleCommand.compile_rci_path(expanded)

    @staticmethod
    def compile_rci_post(arguments: List[str], value_object: Optional[Any] = None) -> RCIPostType:
        if value_object is None:
            value_object = {}

        for argument in reversed(arguments):
            value_object = {argument: value_object}
        return value_object

    def to_rci_post(self, multiple: bool = False) -> Union[RCIPostType, List[RCIPostType]]:
        expanded = self.expanded(multiple=multiple)
        if multiple:
            return list(map(self.compile_rci_post, expanded))
        return self.compile_rci_post(expanded)


APICommandArgType = Union[Mapping[str, Any], Iterable[Mapping[str, Any]], ConsoleCommand, str]
APIRequestRetType = Union[Optional[Mapping[str, Any]], List[Optional[Mapping[str, Any]]]]
CheckKeysType = Iterable[str]


class APIInterface:
    def __init__(self, client: 'APIClient', cmd_stack: Optional[List[str]] = None, sync_get: bool = False):
        self.__client = client
        self.__cmd_stack = cmd_stack or []
        self.__sync_get = sync_get

        _LOGGER.debug('APIINTERFACE %s', self.__cmd_stack)

    def __getattr__(self, item: str) -> 'APIInterface':
        return APIInterface(
            self.__client,
            cmd_stack=[*self.__cmd_stack, item],
            sync_get=self.__sync_get
        )

    def __run_cmd_stack(self, full_command: Mapping[str, Any]):
        client = self.__client
        if self.__sync_get:
            loop = asyncio.get_running_loop()
            return loop.run_until_complete(
                client.api_request(
                    full_command,
                    return_404_as_none=True
                )
            )

        return client.api_request(
            full_command,
            return_404_as_none=True
        )

    def __getitem__(self, item: str):
        full_command = ConsoleCommand.compile_rci_path([*self.__cmd_stack, item])
        return self.__run_cmd_stack(full_command)

    async def __call__(self, *args: str, return_404_as_none: bool = False):
        cmd_stack = [*self.__cmd_stack, *args]
        full_command = ConsoleCommand.compile_rci_post(cmd_stack)

        result = await self.__client.api_request(
            full_command,
            return_404_as_none=return_404_as_none
        )
        if result is not None:
            try:
                for sub_path in cmd_stack:
                    result = result[sub_path]
            except (LookupError, TypeError, ValueError):
                raise InvalidDataException('Invalid data received')
            return result


class APIClient(object):
    def __init__(self, host: str, port: int, username: str, password: str,
                 use_ssl: bool = False, session: Optional[aiohttp.ClientSession] = None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl

        if session is None:
            session = aiohttp.ClientSession(
                cookie_jar=aiohttp.CookieJar(unsafe=True)
            )

        self.session = session

    async def __aenter__(self) -> 'APIClient':
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if not self.closed:
            await self.close()

    @property
    def api(self) -> APIInterface:
        return APIInterface(self)

    @property
    def closed(self) -> bool:
        return self.session.closed

    async def close(self) -> None:
        await self.session.close()

    @classmethod
    def from_telnet_connection(cls, conn: TelnetConnection):
        warnings.warn(
            "This initializer is provided for compatibility purposes. It will be fast "
            "deprecated once further development completes.",
            category=DeprecationWarning
        )

        # noinspection PyProtectedMember
        session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(
                total=conn._timeout
            ),
            cookie_jar=aiohttp.CookieJar(
                unsafe=True
            )
        )

        # noinspection PyProtectedMember
        return cls(
            host=conn._host,
            port=conn._port,
            username=conn._username,
            password=conn._password,
            use_ssl=False,
            session=session
        )

    @property
    def base_url(self) -> str:
        return ('https://' if self.use_ssl else 'http://') + self.host

    async def request(self, path: str, data: Optional[Any] = None, process_status_code: bool = True, **kwargs) \
            -> Tuple[int, Mapping, Any]:
        endpoint = urljoin(self.base_url, path)

        try:
            if isinstance(data, str):
                _LOGGER.debug('REQUEST[%s] POST (%s)', endpoint, data)
                r = await self.session.post(endpoint, data=data, **kwargs)
            elif data:
                _LOGGER.debug('REQUEST[%s] POST (%s)', endpoint, data)
                r = await self.session.post(endpoint, json=data, **kwargs)
            else:
                _LOGGER.debug('REQUEST[%s] GET', endpoint)
                r = await self.session.get(endpoint, **kwargs)

        except aiohttp.ClientError as e:
            raise ConnectionException('Error during HTTP request: %s', e)

        data = await r.text()

        _LOGGER.debug('RESPONSE[%s] %d: %s', endpoint, r.status, data[:75].replace('\n', '\\n') + ('... (continued, total length: %d)' % (len(data),)) if len(data) > 75 else data)

        if process_status_code:
            if r.status == 401:
                raise AuthenticationException('Authentication required')

            elif r.status == 404:
                raise DataNotFoundException('Data or command not found')

            elif r.status == 405:
                raise InvalidCommandException('Invalid command format / Command restricted')

            elif r.status != 200:
                raise ConnectionException('Server responded with unexpected status code (%s): %s',
                                          r.status, data)

        return r.status, r.headers, data

    async def authenticate(self) -> None:
        try:
            response_code, headers, data = await self.request('auth', process_status_code=False)

            if response_code == 401:
                payload = self.username + ':' + headers['X-NDM-Realm'] + ':' + self.password
                pair_hash = md5(payload.encode('utf-8')).hexdigest()

                payload = (headers['X-NDM-Challenge'] + pair_hash)
                pass_hash = sha256(payload.encode('utf-8')).hexdigest()

                response_code, headers, data = await self.request(
                    'auth',
                    {
                        'login': self.username,
                        'password': pass_hash
                    },
                    process_status_code=False
                )

            self._auth_result = (response_code == 200)

        except ConnectionException as e:
            self._auth_result = False
            raise AuthenticationException('Authentication error: %s' % str(e)) from None

    def _load_json(self, data: str) -> Any:
        try:
            return json.loads(data)
        except (json.JSONDecodeError, ValueError, TypeError) as e:
            raise InvalidDataException('Invalid data retrieved (error: %s)' % (e,)) from None

    async def api_request(self, command: Union[str, Mapping[str, Any], ConsoleCommand], return_404_as_none: bool = True) -> Optional[Any]:
        """
        Make a single request to the API.
        :param command: RCI path | RCI post data | Console command object
        :param return_404_as_none:
        :return:
        """
        if isinstance(command, str):
            try:
                response_code, headers, data = await self.request('rci/' + command)
            except DataNotFoundException:
                if return_404_as_none:
                    return None
                raise

            return self._load_json(data)

        if isinstance(command, ConsoleCommand):
            if command.is_multiline():
                raise ValueError('multiline commands must be used with `api_requests` method')
        elif isinstance(command, Mapping):
            command = [command]
        else:
            raise TypeError('provided command of unknown type `%s`' % (type(command),))

        results = await self.api_requests(
            command,
            return_404_as_none=return_404_as_none
        )

        return next(iter(results))

    def _check_key(self, check_key: CheckKeysType, result: Any) -> bool:
        """Checks if target key contains a status field"""
        current_obj = result
        for key in check_key:
            if not isinstance(current_obj, Mapping):
                return True
            if key not in current_obj:
                return True
            current_obj = current_obj[key]

        return not (
                'status' in current_obj
                and isinstance(current_obj['status'], Iterable)
                and any(map(lambda x: isinstance(x, Mapping) and x['status'] == 'error', current_obj['status']))
        )

    async def api_requests(self, commands: Union[ConsoleCommand, Iterable[Union[Mapping[str, Any], str]]],
                           return_404_as_none: bool = True) -> Iterable[Optional[Any]]:
        loop = asyncio.get_running_loop()

        if isinstance(commands, ConsoleCommand):
            rci_paths = commands.to_rci_path(multiple=True)

            coroutines = [
                loop.create_task(
                    self.api_request(path, return_404_as_none=return_404_as_none)
                )
                for path in rci_paths
            ]

            done, pending = await asyncio.wait(
                coroutines,
                return_when=asyncio.FIRST_EXCEPTION
            )

            for pending_task in pending:
                pending_task.cancel()

            results = []
            for done_task in done:
                results.append(done_task.result())

            return results

        cli_tasks = []
        payloads = []

        commands = list(commands)

        for command in commands:
            if isinstance(command, str):
                cli_tasks.append(
                    loop.create_task(
                        self.api_request(
                            command,
                            return_404_as_none=return_404_as_none
                        )
                    )
                )
            else:
                payloads.append(command)

        if payloads:
            cli_tasks.append(
                loop.create_task(
                    self.request('rci/', data=payloads, process_status_code=True)
                )
            )

        done, pending = await asyncio.wait(cli_tasks, return_when=asyncio.FIRST_EXCEPTION)

        for pending_task in pending:
            pending_task.cancel()

        if not payloads:
            return [task.result() for task in done]

        p_response_code, p_headers, p_data = done.pop().result()  # will raise exception at this stage for anything
        p_data = self._load_json(p_data)

        results = []
        done_iterator = iter(done)
        p_result_iterator = iter(p_data)

        for command in commands:
            if isinstance(command, str):
                results.append(next(done_iterator).result())
            else:
                results.append(next(p_result_iterator))

        return results

    async def get_router_info(self) -> RouterInfo:
        """Retrieve general information about the router"""
        data = await self.api_request({'show': {'version': {}}})

        return RouterInfo.from_dict(rget(data, 'show', 'version', default={}))

    async def get_interfaces(self) -> List[InterfaceInfo]:
        """
        Retrieve information about interfaces
        :return: Object containing interface information
        """
        data = await self.api_request({'show': {'interface': {}}})

        return [
            InterfaceInfo.from_dict(v)
            for v in rget(data, 'show', 'interface', default={}).values()
        ]

    async def get_interface_info(self, interface_name: Union[str, Iterable[str]]) -> Union[Optional[InterfaceInfo], List[Optional[InterfaceInfo]]]:
        """
        Retrieve information about specific interface(s)
        :param interface_name: Interface name | List of interface names
        :return: Object containing interface information | Objects containing interface information
        """
        single_interface = isinstance(interface_name, str)
        if single_interface:
            payload = {'name': interface_name}
        else:
            payload = [{'name': interface_name_} for interface_name_ in interface_name]

        data = await self.api_request({'show': {'interface': payload}}, return_404_as_none=True)
        interface_data = rget(data, 'show', 'interface')

        if single_interface:
            return None if interface_data is None else InterfaceInfo.from_dict(interface_data)

        return [
            None if v is None else InterfaceInfo.from_dict(v)
            for v in interface_data
        ]

    async def get_devices(self, *, try_hotspot: bool = True, include_arp: bool = True,
                          include_associated: bool = True) -> List[Device]:
        """
        Fetches a list of connected devices online
        :param try_hotspot: first try `ip hotspot` command.
        :param include_arp: if try_hotspot is False or no hotspot devices detected
        :param include_associated:
        :return:
        """
        devices = []

        if try_hotspot:
            devices = _merge_devices(devices, await self.get_hotspot_devices())
            if len(devices) > 0:
                return devices

        if include_arp:
            devices = _merge_devices(devices, await self.get_arp_devices())

        if include_associated:
            devices = _merge_devices(devices, await self.get_associated_devices())

        return devices

    async def get_hotspot_devices(self) -> List[Device]:
        """
        Get devices associated with a hotspot.
        This is the most precise information on devices known to be online.
        :return: List of devices
        """
        data = await self.__get_hotspot_info()

        return [
            Device.from_dict(v)
            for v in data
        ]

    async def get_arp_devices(self) -> List[Device]:
        data = await self.api_request({'show': {'ip': {'arp': {}}}})

        return [
            Device.from_dict(v)
            for v in rget(data, 'show', 'ip', 'arp', default=[])
        ]

    # noinspection DuplicatedCode
    async def get_associated_devices(self) -> List[Device]:
        data = await self.api_request({'show': {'associations': {}}})
        devices_info = rget(data, 'show', 'associations', 'station', default=[])
        aps = set([info.get('ap') for info in devices_info])

        names_payload = [{'name': ap} for ap in aps]
        data = await self.api_request({'show': {'interface': names_payload}})
        interfaces_info = rget(data, 'show', 'interface', default=[])

        ap_to_bridge = {
            ap: ap_info.get('group') or ap_info.get('interface-name')
            for ap, ap_info in zip(aps, interfaces_info)
        }

        # try enriching the results with hotspot additional info
        hotspot_info = await self.__get_hotspot_info()

        devices = []

        for info in devices_info:
            mac = info.get('mac')
            if mac is not None and info.get('authenticated') in ['1', 'yes', True]:
                host_info = hotspot_info.get(mac, {})

                devices.append(Device(
                    mac=mac.upper(),
                    name=host_info.get('name'),
                    ip=host_info.get('ip'),
                    interface=ap_to_bridge.get(info.get('ap'), info.get('ap'))
                ))

        return devices

    async def __get_hotspot_info(self) -> Mapping[str, Mapping[str, Any]]:
        try:
            data = await self.api_request({'show': {'ip': {'hotspot': {}}}})
        except (InvalidCommandException, DataNotFoundException):
            return {}

        return {
            hosts_data['mac']: hosts_data
            for hosts_data in rget(data, 'show', 'ip', 'hotspot', 'host', default=[])
        }


class Client(object):
    def __init__(self, connection: Connection):
        self._connection = connection

    def get_router_info(self) -> RouterInfo:
        info = _parse_dict_lines(self._connection.run_command(_VERSION_CMD))

        _LOGGER.debug('Raw router info: %s', str(info))
        assert isinstance(info, dict), 'Router info response is not a dictionary'
        
        return RouterInfo.from_dict(info)

    def get_interfaces(self) -> List[InterfaceInfo]:
        collection = _parse_collection_lines(self._connection.run_command(_INTERFACES_CMD))

        _LOGGER.debug('Raw interfaces info: %s', str(collection))
        assert isinstance(collection, list), 'Interfaces info response is not a collection'

        return [InterfaceInfo.from_dict(info) for info in collection]

    def get_interface_info(self, interface_name) -> Optional[InterfaceInfo]:
        info = _parse_dict_lines(self._connection.run_command(_INTERFACE_CMD % interface_name))

        _LOGGER.debug('Raw interface info: %s', str(info))
        assert isinstance(info, dict), 'Interface info response is not a dictionary'

        if 'id' in info:
            return InterfaceInfo.from_dict(info)

        return None

    def get_devices(self, *, try_hotspot=True, include_arp=True, include_associated=True) -> List[Device]:
        """
            Fetches a list of connected devices online
            :param try_hotspot: first try `ip hotspot` command.
            This is the most precise information on devices known to be online
            :param include_arp: if try_hotspot is False or no hotspot devices detected
            :param include_associated:
            :return:
        """
        devices = []

        if try_hotspot:
            devices = _merge_devices(devices, self.get_hotspot_devices())
            if len(devices) > 0:
                return devices

        if include_arp:
            devices = _merge_devices(devices, self.get_arp_devices())

        if include_associated:
            devices = _merge_devices(devices, self.get_associated_devices())

        return devices

    def get_hotspot_devices(self) -> List[Device]:
        hotspot_info = self.__get_hotspot_info()

        return [Device(
            mac=info.get('mac').upper(),
            name=info.get('name'),
            ip=info.get('ip'),
            interface=info['interface'].get('name', '')
        ) for info in hotspot_info.values() if 'interface' in info and info.get('link') == 'up']

    def get_arp_devices(self) -> List[Device]:
        lines = self._connection.run_command(_ARP_CMD)

        result = _parse_table_lines(lines, _ARP_REGEX)

        return [Device(
            mac=info.get('mac').upper(),
            name=info.get('name') or None,
            ip=info.get('ip'),
            interface=info.get('interface')
        ) for info in result if info.get('mac') is not None]

    def get_associated_devices(self):
        associations = _parse_dict_lines(self._connection.run_command(_ASSOCIATIONS_CMD))

        items = associations.get('station', [])
        if not isinstance(items, list):
            items = [items]

        aps = set([info.get('ap') for info in items])

        ap_to_bridge = {}
        for ap in aps:
            ap_info = _parse_dict_lines(self._connection.run_command(_INTERFACE_CMD % ap))
            ap_to_bridge[ap] = ap_info.get('group') or ap_info.get('interface-name')

        # try enriching the results with hotspot additional info
        hotspot_info = self.__get_hotspot_info()

        devices = []

        for info in items:
            mac = info.get('mac')
            if mac is not None and info.get('authenticated') in ['1', 'yes']:
                host_info = hotspot_info.get(mac)

                devices.append(Device(
                    mac=mac.upper(),
                    name=host_info.get('name') if host_info else None,
                    ip=host_info.get('ip') if host_info else None,
                    interface=ap_to_bridge.get(info.get('ap'), info.get('ap'))
                ))

        return devices

    # hotspot info is only available in newest firmware (2.09 and up) and in router mode
    # however missing command error will lead to empty dict returned
    def __get_hotspot_info(self):
        info = _parse_dict_lines(self._connection.run_command(_HOTSPOT_CMD))

        items = info.get('host', [])
        if not isinstance(items, list):
            items = [items]

        return {item.get('mac'): item for item in items}


def _str(value: Optional[any]) -> Optional[str]:
    if value is None:
        return None

    return str(value)


def _int(value: Optional[any]) -> Optional[int]:
    if value is None:
        return None

    return int(value)


def _merge_devices(*lists: List[Device]) -> List[Device]:
    res = {}
    for l in lists:
        for dev in l:
            key = (dev.interface, dev.mac)
            if key in res:
                old_dev = res.get(key)
                res[key] = Device(
                    mac=old_dev.mac,
                    name=old_dev.name or dev.name,
                    ip=old_dev.ip or dev.ip,
                    interface=old_dev.interface
                )
            else:
                res[key] = dev

    return list(res.values())


def _parse_table_lines(lines: List[str], regex: re) -> List[Dict[str, any]]:
    """Parse the lines using the given regular expression.
     If a line can't be parsed it is logged and skipped in the output.
    """
    results = []
    for line in lines:
        match = regex.search(line)
        if not match:
            _LOGGER.debug('Could not parse line: %s', line)
            continue
        results.append(match.groupdict())
    return results


def _fix_continuation_lines(lines: List[str]) -> List[str]:
    indent = 0
    continuation_possible = False
    fixed_lines = []  # type: List[str]
    for line in lines:
        if len(line.strip()) == 0:
            continue

        if continuation_possible and len(line[:indent].strip()) == 0:
            prev_line = fixed_lines.pop()
            line = prev_line.rstrip() + line[(indent + 1):].lstrip()
        else:
            assert ':' in line, 'Found a line with no colon when continuation is not possible: ' + line

            colon_pos = line.index(':')
            comma_pos = line.index(',') if ',' in line[:colon_pos] else None
            indent = comma_pos if comma_pos is not None else colon_pos

            continuation_possible = len(line[(indent + 1):].strip()) > 0

        fixed_lines.append(line)

    return fixed_lines


def _parse_dict_lines(lines: List[str]) -> Dict[str, any]:
    response = {}
    indent = 0
    stack = [(None, indent, response)]  # type: List[Tuple[str, int, Union[str, dict]]]
    stack_level = 0

    for line in _fix_continuation_lines(lines):
        if len(line.strip()) == 0:
            continue

        _LOGGER.debug(line)

        # exploding the line
        colon_pos = line.index(':')
        comma_pos = line.index(',') if ',' in line[:colon_pos] else None
        key = line[:colon_pos].strip()
        value = line[(colon_pos + 1):].strip()
        new_indent = comma_pos if comma_pos is not None else colon_pos

        # assuming line is like 'mac-access, id = Bridge0: ...'
        if comma_pos is not None:
            key = line[:comma_pos].strip()

            value = {key: value} if value != '' else {}

            args = line[comma_pos + 1:colon_pos].split(',')
            for arg in args:
                sub_key, sub_value = [p.strip() for p in arg.split('=', 1)]
                value[sub_key] = sub_value

        # up and down the stack
        if new_indent > indent:  # new line is a sub-value of parent
            stack_level += 1
            indent = new_indent
            stack.append(None)
        else:
            while new_indent < indent and len(stack) > 0:  # getting one level up
                stack_level -= 1
                stack.pop()
                _, indent, _ = stack[stack_level]

        if stack_level < 1:
            break

        assert indent == new_indent, 'Irregular indentation detected'

        stack[stack_level] = key, indent, value

        # current containing object
        obj_key, obj_indent, obj = stack[stack_level - 1]

        # we are the first child of the containing object
        if not isinstance(obj, dict):
            # need to convert it from empty string to empty object
            assert obj == '', 'Unexpected nested object format'
            _, _, parent_obj = stack[stack_level - 2]
            obj = {}

            # containing object might be in a list also
            if isinstance(parent_obj[obj_key], list):
                parent_obj[obj_key].pop()
                parent_obj[obj_key].append(obj)
            else:
                parent_obj[obj_key] = obj
            stack[stack_level - 1] = obj_key, obj_indent, obj

        # current key is already in object means there should be an array of values
        if key in obj:
            if not isinstance(obj[key], list):
                obj[key] = [obj[key]]

            obj[key].append(value)
        else:
            obj[key] = value

    return response


def _parse_collection_lines(lines: List[str]) -> List[Dict[str, any]]:
    _HEADER_REGEXP = re.compile(r'^(\w+),\s*name\s*=\s*\"([^"]+)\"')

    result = []
    item_lines = []  # type: List[str]
    for line in lines:
        if len(line.strip()) == 0:
            continue

        match = _HEADER_REGEXP.match(line)
        if match:
            if len(item_lines) > 0:
                result.append(_parse_dict_lines(item_lines))
                item_lines = []
        else:
            item_lines.append(line)

    if len(item_lines) > 0:
        result.append(_parse_dict_lines(item_lines))

    return result
