import abc
import socket
from struct import Struct
from typing import ClassVar
from dataclasses import dataclass, field

OT_CONFIG = 0x01
OT_LOAD_BALANCING = 0x02
OT_IPV4_ENDPOINT = 0x04


class BaseOption(abc.ABC):

    @abc.abstractmethod
    def pack(self) -> bytes:
        raise NotImplementedError("Must implement pack() method.")

    @abc.abstractmethod
    def __len__(self) -> int:
        """
        Return the length of the option in bytes.
        """
        raise NotImplementedError("Must implement __len__() method.")

    @classmethod
    @abc.abstractmethod
    def unpack(cls, data: bytes) -> 'BaseOption':
        raise NotImplementedError("Must implement unpack() method.")


def encode_config(config: dict[str, str]) -> bytes:
    str_configs = [f"{k}={v}" for k, v in config.items()]
    data = b""
    for str_config in str_configs:
        str_config_len = len(str_config)
        if str_config_len > 255:
            raise ValueError("Configuration option value is too long.")
        data += bytes([str_config_len]) + str_config.encode()
    data += b"\x00"
    return data


def decode_config(data: bytes) -> dict[str, str]:
    config = {}
    while data:
        str_len = data[0]
        if str_len == 0:
            break
        str_config = data[1:str_len + 1].decode()
        k, v = str_config.split("=")
        config[k] = v
        data = data[str_len + 1:]
    return config


@dataclass
class ConfigOption(BaseOption):
    config: dict[str, str]
    can_discard: bool = field(default=True)

    _st: ClassVar[Struct] = Struct("!HBB")

    def pack(self) -> bytes:
        config_bytes = encode_config(self.config)
        length = 0x0001 + len(config_bytes)
        type = OT_CONFIG
        discard_flag = 0x80 if self.can_discard else 0x00
        return ConfigOption._st.pack(length, type, discard_flag) + config_bytes

    def __len__(self) -> int:
        return self._st.size + len(encode_config(self.config))

    @classmethod
    def unpack(cls, data: bytes) -> 'ConfigOption':
        fixed_size = ConfigOption._st.size
        if len(data) < fixed_size:
            raise ValueError("Invalid configuration option data.")
        length, type, discard_flag = ConfigOption._st.unpack(
            data[:fixed_size])
        if type != OT_CONFIG:
            raise ValueError("Invalid configuration option type.")

        # can_discard = ((int(discard_flag) >> 7) & 1) == 1
        can_discard = ((discard_flag >> 7) & 1) == 1
        config = decode_config(data[fixed_size:])
        return cls(config, can_discard)


@dataclass
class LoadBalancingOption(BaseOption):
    priority: int
    weight: int
    can_discard: bool = field(default=True)

    _st: ClassVar[Struct] = Struct("!HBBHH")

    def pack(self) -> bytes:
        length = 0x0005
        type = OT_LOAD_BALANCING
        discard_flag = 0x80 if self.can_discard else 0x00
        return LoadBalancingOption._st.pack(length, type, discard_flag,
                                            self.priority, self.weight)

    def __len__(self) -> int:
        return self._st.size

    @classmethod
    def unpack(cls, data: bytes) -> 'LoadBalancingOption':
        if len(data) != cls._st.size:
            raise ValueError("Invalid LoadBalancingOption data")
        length, type, discard_flag, priority, weight = cls._st.unpack(
            data[:cls._st.size])
        if type != OT_LOAD_BALANCING:
            raise ValueError("Invalid LoadBalancingOption type")
        can_discard = ((discard_flag >> 7) & 1) == 1
        return cls(priority, weight, can_discard)


# string -> int
L4_PROTO_S2I = {
    "TCP": 0x06,
    "UDP": 0x11,
}
L4_PROTO_I2S = {v: k for k, v in L4_PROTO_S2I.items()}


@dataclass
class IPv4EndpointOption(BaseOption):
    addr: str
    l4_proto: str
    port: int

    _st: ClassVar[Struct] = Struct("!HBB4sxBH")

    def pack(self) -> bytes:
        length = 0x0009
        type = OT_IPV4_ENDPOINT
        discard_flag = 0x00  # not discardable
        addr_bytes = socket.inet_pton(socket.AF_INET, self.addr)
        l4_proto_int = L4_PROTO_S2I.get(self.l4_proto.upper(), None)
        if l4_proto_int is None:
            raise ValueError(f"unknown l4 protocol: {self.l4_proto}")

        return IPv4EndpointOption._st.pack(length, type, discard_flag,
                                           addr_bytes,
                                           l4_proto_int, self.port)

    def __len__(self) -> int:
        return self._st.size

    @classmethod
    def unpack(cls, data: bytes) -> 'IPv4EndpointOption':
        if len(data) < cls._st.size:
            raise ValueError(f"invalid data length: {len(data)}")
        # 允许传入过长字节
        length, type, discard_flag, \
            addr_bytes, l4_proto_int, port = cls._st.unpack(
                data[:cls._st.size])
        if type != OT_IPV4_ENDPOINT:
            raise ValueError(f"invalid type: {type}")
        # can_discard = ((discard_flag >> 7) & 1) == 1

        addr = socket.inet_ntoa(addr_bytes)
        l4_proto = L4_PROTO_I2S.get(l4_proto_int, None)
        if l4_proto is None:
            raise ValueError(f"invalid l4_proto: {l4_proto_int}")
        return cls(addr, l4_proto, port)


OPTION_TYPE_MAP: dict[int, type[BaseOption]] = {
    OT_CONFIG: ConfigOption,
    OT_LOAD_BALANCING: LoadBalancingOption,
    OT_IPV4_ENDPOINT: IPv4EndpointOption,
}


def unpack_someip_sd_option(data: bytes):
    option_type = data[2]
    option_class = OPTION_TYPE_MAP.get(option_type, None)
    if option_class is None:
        raise ValueError(f"Unknown entry type: {option_type}")

    return option_class.unpack(data)


def test_config_option():
    opt1 = ConfigOption({
        "abc": "x",
        "def": "123",
    })
    print(opt1)
    print(opt1.pack().hex())

    opt2 = ConfigOption.unpack(opt1.pack())
    print(opt2)
    assert opt1 == opt2


def test_load_balancing_option():
    opt1 = LoadBalancingOption(0xAABB, 0xCCDD)
    print(opt1)
    print(opt1.pack().hex())
    opt2 = LoadBalancingOption.unpack(opt1.pack())
    print(opt2)
    assert opt1 == opt2


def test_ipv4_endpoint_option():
    opt1 = IPv4EndpointOption("192.168.225.100", "UDP", 1884)
    print(opt1)
    print(opt1.pack().hex())
    opt2 = IPv4EndpointOption.unpack(opt1.pack())
    print(opt2)
    assert opt1 == opt2


if __name__ == "__main__":
    test_config_option()
    test_load_balancing_option()
    test_ipv4_endpoint_option()
