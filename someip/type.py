from struct import Struct
from dataclasses import dataclass, field
from typing import ClassVar


@dataclass
class SOMEIPPacket:
    service_id: int
    """ 2Byte """

    method_id: int
    """ 2Byte """

    length: int = field(init=False)
    """
    4Byte

    从下一个字段开始计算长度
    """

    client_id: int
    """ 2Byte """
    session_id: int
    """ 2Byte """
    protocol_version: int
    """ 1Byte """
    interface_version: int
    """ 1Byte """
    message_type: int
    """ 1Byte """
    return_code: int
    """ 1Byte """
    payload: bytes

    _struct: ClassVar[Struct] = Struct("!HHIHHBBBB")

    def __post_init__(self):
        self.length = 8 + len(self.payload)

    def pack(self) -> bytes:
        return SOMEIPPacket._struct.pack(
            self.service_id, self.method_id,
            self.length,
            self.client_id, self.session_id,
            self.protocol_version, self.interface_version,
            self.message_type, self.return_code) + self.payload

    @classmethod
    def unpack(cls, data: bytes):
        service_id, method_id, length, client_id, session_id, \
            protocol_version, interface_version, \
            message_type, return_code = SOMEIPPacket._struct.unpack(data[:16])
        payload = data[16:]
        return cls(service_id, method_id, client_id, session_id,
                   protocol_version, interface_version,
                   message_type, return_code, payload)
