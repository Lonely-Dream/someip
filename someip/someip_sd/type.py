import struct
from dataclasses import dataclass, field

from .entry import (
    BaseEntry,
    unpack_someip_sd_entry,
)
from .option import (
    BaseOption,
    unpack_someip_sd_option,
)


@dataclass
class SomeIpSDPacket:
    is_reboot: bool
    entries: list[BaseEntry]
    options: list[BaseOption] = field(default_factory=list)

    def pack(self) -> bytes:
        is_unicast = True
        flag = 0
        flag |= (1 if self.is_reboot else 0) << 7
        flag |= (1 if is_unicast else 0) << 6
        entries_bytes = b"".join([entry.pack() for entry in self.entries])
        entries_length = len(entries_bytes)
        options_bytes = b"".join([option.pack() for option in self.options])
        options_length = len(options_bytes)
        _ = [
            struct.pack('!Bxxx', flag),
            entries_length.to_bytes(4, "big"),
            entries_bytes,
            options_length.to_bytes(4, "big"),
            options_bytes,
        ]
        return b"".join(_)

    @classmethod
    def unpack(cls, data: bytes) -> 'SomeIpSDPacket':
        flag = data[0]
        data = data[1:]
        is_reboot = bool(flag & 0b10000000)
        # is_unicast = bool(flag & 0b01000000)

        data = data[3:]  # 跳过保留字节

        entries_length = int.from_bytes(data[:4], "big")
        data = data[4:]
        entries_bytes = data[:entries_length]
        data = data[entries_length:]
        # Entry 为固定大小 16 字节
        entries = []
        while entries_bytes:
            entry = unpack_someip_sd_entry(entries_bytes[:16])
            entries.append(entry)
            entries_bytes = entries_bytes[16:]

        options_length = int.from_bytes(data[:4], "big")
        data = data[4:]
        options_bytes = data[:options_length]
        options = []
        while options_bytes:
            option = unpack_someip_sd_option(options_bytes)
            options.append(option)
            options_bytes = options_bytes[len(option):]

        return cls(is_reboot, entries, options)
