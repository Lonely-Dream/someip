from dataclasses import dataclass, field

from .entry import (
    BaseEntry
)
from .option import (
    BaseOption
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
            flag.to_bytes(1, "big"),
            entries_length.to_bytes(4, "big"),
            entries_bytes,
            options_length.to_bytes(4, "big"),
            options_bytes,
        ]
        return b"".join(_)
