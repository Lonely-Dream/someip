import someip


def test_someip_packet():
    packet = someip.SOMEIPPacket(
        service_id=0x0101,
        method_id=0x0101,
        client_id=0xFE,
        session_id=1,
        protocol_version=0x01,
        interface_version=0x01,
        message_type=0,
        return_code=0,
        payload=b''
    )
    print(packet.pack().hex())


def test_someip_sd_entry():
    from someip.someip_sd.entry import (
        SOMEIPSDEventgroupEntry,
        ET_SUBSCRIBE,
        unpack_someip_sd_entry,
    )
    a = SOMEIPSDEventgroupEntry(
        type=ET_SUBSCRIBE,
        index1=1,
        index2=2,
        num_option1=3,
        num_option2=4,
        service_id=0xABCD,
        instance_id=0xFFFF,
        major_version=0x01,
        ttl=0x112233,
        counter=5,
        eventgroup_id=0xAABB
    )
    data = a.pack().hex()
    print(data)
    b = unpack_someip_sd_entry(bytes.fromhex(data))
    print(b.__class__)
    print(b.pack().hex())


def test_someip_sd_option():
    from someip.someip_sd.option import (
        ConfigOption,
        LoadBalancingOption,
        IPv4EndpointOption,
        unpack_someip_sd_option,
    )
    opts = [
        ConfigOption({"a": "b", "c": "d"}),
        LoadBalancingOption(0xAABB, 0xCCDD),
        IPv4EndpointOption("192.168.225.100", "udp", 1884),
    ]
    [print(opt) for opt in opts]
    [print(opt.pack().hex()) for opt in opts]
    opt = unpack_someip_sd_option(opts[2].pack())
    print(opt)
    print(opt.pack().hex())


if __name__ == "__main__":
    test_someip_packet()
    test_someip_sd_entry()
    test_someip_sd_option()
