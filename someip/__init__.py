import socket
import struct
import threading

from typing import Callable

from .type import SOMEIPPacket
from .someip_sd import (
    SomeIpSDPacket,
    BaseEntry,
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


class SomeIpClient:
    client_ip: str
    client_port: int
    client_id: int
    multicast_ip: str
    multicast_port: int

    callback: Callable[[SOMEIPPacket], None] | None

    session_id: int
    sock: socket.socket
    recv_thread: threading.Thread

    def __init__(self, multicast_ip: str, multicast_port: int,
                 client_ip: str | None = None,
                 client_port: int = 4444,
                 client_id: int = 0xFE,
                 callback: Callable[[SOMEIPPacket], None] | None = None
                 ) -> None:
        if client_ip is None:
            client_ip = socket.gethostbyname(socket.gethostname())
            print(f"client_ip is None, use localhost. {client_ip}")
        self.client_ip = client_ip
        self.client_port = client_port
        self.client_id = client_id
        self.multicast_ip = multicast_ip
        self.multicast_port = multicast_port

        self.callback = callback

        self.session_id = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.sock.bind((self.client_ip, self.client_port))
        # self.sock.bind(("", self.client_port))
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
                timeout: int = 5):

        request_packet = SOMEIPPacket(
            service_id=service_id,
            method_id=method_id,
            client_id=self.client_id,
            session_id=self.session_id,
            protocol_version=0x01,
            interface_version=0x01,
            message_type=MT_REQUEST,
            return_code=0x00,
            payload=payload
        )

        self.sock.sendto(request_packet.pack(), (server_ip, server_port))

    def recv_loop(self) -> None:
        while True:
            data, addr = self.sock.recvfrom(4 * 0x400)
            print("recv data from ", addr)

            if self.callback is not None:
                self.callback(SOMEIPPacket.unpack(data))

    def subscribe(self):
        pass
