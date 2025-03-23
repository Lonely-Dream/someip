from .type import SOMEIPPacket

from someip_sd import (
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
