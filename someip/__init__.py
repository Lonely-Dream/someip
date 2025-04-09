import socket
import struct
import threading

from typing import Callable, TypeVar

from .type import SOMEIPPacket
from .someip_sd import (
    SomeIpSDPacket,
    ET_SUBSCRIBE,
    ET_STOP_SUBSCRIBE_EVENTGROUP,
    SOMEIPSDEventgroupEntry,
    BaseEntry,
    IPv4EndpointOption,
    BaseOption,
)

MT_REQUEST = 0x00
MT_REQUEST_NO_RETURN = 0x01
MT_NOTIFICATION = 0x02
MT_RESPONSE = 0x80
MT_ERROR = 0x81
MT_TP_REQUEST = 0x20
MT_TP_REQUEST_NO_RETURN = 0x21
MT_TP_NOTIFICATION = 0x22
MT_TP_RESPONSE = 0xA0
MT_TP_ERROR = 0xA1


def build_someip_sd_packet(
        client_id: int,
        entries: list[BaseEntry],
        options: list[BaseOption] | None) -> SOMEIPPacket:
    someip_sd_packet = SomeIpSDPacket(
        is_reboot=True,
        entries=entries,
        options=options if options is not None else [],
    )
    someip_packet = SOMEIPPacket(
        service_id=0xFFFF,
        method_id=0x8100,
        client_id=client_id,
        session_id=1,
        protocol_version=0x01,
        interface_version=0x01,
        message_type=MT_NOTIFICATION,
        return_code=0x00,
        payload=someip_sd_packet.pack()
    )
    return someip_packet


# __all__ = [
#     'SOMEIPPacket',
# ]

def request(
    server_ip: str,
    server_port: int,
    service_id: int,
    method_id: int,
    payload: bytes,
    client_id: int = 0xFE,
    timeout: int = 5
) -> SOMEIPPacket:

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    request_packet = SOMEIPPacket(
        service_id=service_id,
        method_id=method_id,
        client_id=client_id,
        session_id=1,
        protocol_version=0x01,
        interface_version=0x01,
        message_type=MT_REQUEST,
        return_code=0x00,
        payload=payload
    )

    sock.sendto(request_packet.pack(), (server_ip, server_port))

    while True:
        data, addr = sock.recvfrom(1024)
        if addr == (server_ip, server_port):
            response_packet = SOMEIPPacket.unpack(data)
            break

    return response_packet


CallbackType = TypeVar("CallbackType", bound=Callable[[SOMEIPPacket], None])


class SomeIpClient:
    client_ip: str
    client_id: int
    multicast_ip: str
    multicast_port: int
    protocol_version: int
    interface_version: int

    generic_callback: CallbackType | None
    callback_map: dict[int, CallbackType]
    """
    service_id => callback
    """

    session_id: int
    sock: socket.socket
    recv_thread: threading.Thread

    def __init__(self, multicast_ip: str, multicast_port: int,
                 client_ip: str | None = None,
                 client_id: int = 0xFE,
                 protocol_version: int = 0x01,
                 interface_version: int = 0x01,
                 generic_callback: CallbackType | None = None
                 ) -> None:
        if client_ip is None:
            client_ip = socket.gethostbyname(socket.gethostname())
            print(f"client_ip is None, use localhost. {client_ip}")
        self.client_ip = client_ip
        self.client_id = client_id
        self.multicast_ip = multicast_ip
        self.multicast_port = multicast_port
        self.protocol_version = protocol_version
        self.interface_version = interface_version

        self.generic_callback = generic_callback
        self.callback_map = {}

        self.session_id = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 允许重用端口
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("", self.multicast_port))

        # 加入多播组
        mreq = struct.pack(
            '4sL',
            socket.inet_aton(self.multicast_ip),
            socket.INADDR_ANY)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        self.recv_thread = threading.Thread(target=self.recv_loop, daemon=True)
        self.recv_thread.start()

    def request(self,
                server_ip: str,
                server_port: int,
                service_id: int,
                method_id: int,
                payload: bytes,
                protocol_version: int | None = None,
                interface_version: int | None = None,
                callback: CallbackType | None = None,
                timeout: int = 5):

        if protocol_version is None:
            protocol_version = self.protocol_version
        if interface_version is None:
            interface_version = self.interface_version

        request_packet = SOMEIPPacket(
            service_id=service_id,
            method_id=method_id,
            client_id=self.client_id,
            session_id=self.session_id,
            protocol_version=protocol_version,
            interface_version=interface_version,
            message_type=MT_REQUEST,
            return_code=0x00,
            payload=payload
        )

        if callback is not None:
            self.callback_map[service_id] = callback

        self.sock.sendto(request_packet.pack(), (server_ip, server_port))
        self.session_id += 1

    def recv_loop(self) -> None:
        while True:
            data, addr = self.sock.recvfrom(4 * 0x400)
            # print("recv data from ", addr)
            packet = SOMEIPPacket.unpack(data)

            if self.generic_callback is not None:
                self.generic_callback(packet)

            callback = self.callback_map.get(packet.service_id, None)
            if callback is not None:
                callback(packet)

    def subscribe(self,
                  server_ip: str,
                  service_id: int,
                  eventgroup_id: int,
                  instance_id: int = 0xFFFF,
                  major_version: int = 0xFF,
                  ttl: int = 0xFFFFFF,
                  protocol_version: int | None = None,
                  interface_version: int | None = None,
                  callback: CallbackType | None = None,
                  ):
        if protocol_version is None:
            protocol_version = self.protocol_version
        if interface_version is None:
            interface_version = self.interface_version
        if callback is not None:
            self.callback_map[service_id] = callback

        sd_entry = SOMEIPSDEventgroupEntry(
            type=ET_SUBSCRIBE,
            index1=0, index2=0,
            num_option1=1, num_option2=0,
            service_id=service_id,
            instance_id=instance_id,
            major_version=major_version,
            ttl=ttl,
            counter=0,
            eventgroup_id=eventgroup_id
        )
        # 使用组播端口作为客户端端口
        sd_option = IPv4EndpointOption(
            self.client_ip, "UDP", self.multicast_port)

        someip_sd_packet = SomeIpSDPacket(
            is_reboot=True,
            entries=[sd_entry],
            options=[sd_option],
        )

        packet = SOMEIPPacket(
            service_id=0xFFFF,
            method_id=0x8100,
            client_id=self.client_id,
            session_id=self.session_id,
            protocol_version=protocol_version,
            interface_version=interface_version,
            message_type=MT_NOTIFICATION,
            return_code=0x00,
            payload=someip_sd_packet.pack()
        )

        self.sock.sendto(packet.pack(), (server_ip, self.multicast_port))
        self.session_id += 1

    def stop_subscribe(self,
                       server_ip: str,
                       service_id: int,
                       eventgroup_id: int,
                       instance_id: int = 0xFFFF,
                       major_version: int = 0xFF,
                       protocol_version: int | None = None,
                       interface_version: int | None = None,
                       ):
        if protocol_version is None:
            protocol_version = self.protocol_version
        if interface_version is None:
            interface_version = self.interface_version

        sd_entry = SOMEIPSDEventgroupEntry(
            type=ET_STOP_SUBSCRIBE_EVENTGROUP,
            index1=0, index2=0,
            num_option1=1, num_option2=0,
            service_id=service_id,
            instance_id=instance_id,
            major_version=major_version,
            ttl=0x000000,
            counter=0,
            eventgroup_id=eventgroup_id
        )
        # 使用组播端口作为客户端端口
        sd_option = IPv4EndpointOption(
            self.client_ip, "UDP", self.multicast_port)

        someip_sd_packet = SomeIpSDPacket(
            is_reboot=True,
            entries=[sd_entry],
            options=[sd_option],
        )

        packet = SOMEIPPacket(
            service_id=0xFFFF,
            method_id=0x8100,
            client_id=self.client_id,
            session_id=self.session_id,
            protocol_version=protocol_version,
            interface_version=interface_version,
            message_type=MT_NOTIFICATION,
            return_code=0x00,
            payload=someip_sd_packet.pack()
        )

        self.sock.sendto(packet.pack(), (server_ip, self.multicast_port))
        self.session_id += 1
