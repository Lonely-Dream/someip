import abc
from struct import Struct
from typing import ClassVar
from dataclasses import dataclass

ET_FIND_SERVICE = 0x00
ET_OFFER_SERVICE = 0x01
ET_STOP_OFFER_SERVICE = 0x01

ET_SUBSCRIBE = 0x06
ET_STOP_SUBSCRIBE_EVENTGROUP = 0x06
ET_SUBSCRIBE_ACK = 0x07
ET_SUBSCRIBE_EVENTGROUP_NACK = 0x07


class BaseEntry(abc.ABC):
    @abc.abstractmethod
    def pack(self) -> bytes:
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def unpack(cls, data: bytes) -> 'BaseEntry':
        raise NotImplementedError()


@dataclass
class SOMEIPSDServiceEntry(BaseEntry):
    type: int
    index1: int
    index2: int
    num_option1: int
    num_option2: int
    service_id: int
    instance_id: int
    major_version: int
    ttl: int
    minor_version: int

    _st: ClassVar[Struct] = Struct("!BBBBHHB3sI")

    def pack(self) -> bytes:
        num_option = (self.num_option1 << 4) | self.num_option2
        ttl_bytes = self.ttl.to_bytes(3, "big")
        return SOMEIPSDServiceEntry._st.pack(
            self.type, self.index1, self.index2, num_option,
            self.service_id, self.instance_id,
            self.major_version, ttl_bytes,
            self.minor_version)

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) != SOMEIPSDServiceEntry._st.size:
            raise ValueError("Data length does not match expected size.")

        type, index1, index2, num_option, \
            service_id, instance_id, \
            major_version, ttl_bytes, \
            minor_version = SOMEIPSDServiceEntry._st.unpack(data)
        num_option1 = num_option >> 4
        num_option2 = num_option & 0x0F
        ttl = int.from_bytes(ttl_bytes, 'big')
        return cls(type, index1, index2, num_option1, num_option2,
                   service_id, instance_id,
                   major_version, ttl,
                   minor_version)


@dataclass
class SOMEIPSDEventgroupEntry(BaseEntry):
    type: int
    index1: int
    index2: int
    num_option1: int
    num_option2: int
    service_id: int
    instance_id: int
    major_version: int
    ttl: int
    counter: int
    eventgroup_id: int

    _st: ClassVar[Struct] = Struct("!BBBBHHB3sHH")

    def pack(self) -> bytes:
        num_option = (self.num_option1 << 4) | self.num_option2
        ttl_bytes = self.ttl.to_bytes(3, "big")
        counter = self.counter & 0x0F
        return SOMEIPSDEventgroupEntry._st.pack(
            self.type, self.index1, self.index2, num_option,
            self.service_id, self.instance_id,
            self.major_version, ttl_bytes,
            counter, self.eventgroup_id)

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) != SOMEIPSDEventgroupEntry._st.size:
            raise ValueError("Data length does not match expected size.")

        type, index1, index2, num_option, \
            service_id, instance_id, \
            major_version, ttl_bytes, \
            counter, eventgroup_id = SOMEIPSDEventgroupEntry._st.unpack(data)
        num_option1 = num_option >> 4
        num_option2 = num_option & 0x0F
        ttl = int.from_bytes(ttl_bytes, 'big')
        counter &= 0x0F
        return cls(type, index1, index2, num_option1, num_option2,
                   service_id, instance_id,
                   major_version, ttl,
                   counter, eventgroup_id)


ENTRY_TYPE_MAP: dict[int, type[BaseEntry]] = {
    ET_FIND_SERVICE: SOMEIPSDServiceEntry,
    ET_OFFER_SERVICE: SOMEIPSDServiceEntry,
    ET_STOP_OFFER_SERVICE: SOMEIPSDServiceEntry,

    ET_SUBSCRIBE: SOMEIPSDEventgroupEntry,
    ET_STOP_SUBSCRIBE_EVENTGROUP: SOMEIPSDEventgroupEntry,
    ET_SUBSCRIBE_ACK: SOMEIPSDEventgroupEntry,
    ET_SUBSCRIBE_EVENTGROUP_NACK: SOMEIPSDEventgroupEntry,
}


def unpack_someip_sd_entry(data: bytes):
    entry_type = data[0]
    if entry_type not in ENTRY_TYPE_MAP:
        raise ValueError(f"Unknown entry type: {entry_type}")

    return ENTRY_TYPE_MAP[entry_type].unpack(data)
