class BusMirrorData:
    def __init__(self):
        self.Timestamp = 0
        self.NetworkStateAvailable = 0
        self.FrameIDAvailable = 0
        self.PayloadAvailable = 0
        self.NetworkType = 0
        self.Netw_ID = 0
        self.Netw_State = 0
        self.FrameID = 0
        self.Pay_Length = 0
        self.data = bytes()


class BusMirror:
    def __init__(self, max_size=500):
        self.max_size = max_size
        self.ProtocolVersion = 0
        self.SequenceNumber = 0
        self.HeaderTimestamp = 0
        self.DataLength = 0
        self.bus_data = []  # 假设最大100个数据
        self.bus_data_num = 0


def unpack_bus_mirror(input_payload, input_payload_length, offset=12):
    """
    解包总线镜像数据

    Args:
        input_payload: 输入的字节数组
        input_payload_length: 输入数据长度
        offset: 偏移量

    Returns:
        tuple: (状态码, bus_mirror对象)
        状态码: 1表示成功，负数表示各种错误
    """
    bus_mirror = BusMirror()

    # 检查偏移量
    if offset > input_payload_length - 2:
        return None

    bus_mirror.ProtocolVersion = input_payload[0]
    bus_mirror.SequenceNumber = input_payload[1]
    bus_mirror.HeaderTimestamp = int.from_bytes(input_payload[2:12], byteorder='big')


    # 获取数据长度
    bus_mirror.DataLength = int.from_bytes(input_payload[offset:offset+2], byteorder='big')

    # 检查数据长度
    if input_payload_length - offset - bus_mirror.DataLength == 2:
        pass
    elif input_payload_length - offset - bus_mirror.DataLength > 2:
        return None  # 长度过长
    else:
        return None  # 数据不完整

    busmirror_message_num = 0
    unpacked_byte = offset + 2

    while True:
        # 解析时间戳
        if busmirror_message_num > bus_mirror.max_size:
            print("bus_mirror数据长度大于max_size")
            return bus_mirror
        bus_mirror.bus_data.append(BusMirrorData())
        bus_mirror.bus_data[busmirror_message_num].Timestamp = (
            int.from_bytes(input_payload[unpacked_byte:unpacked_byte+2], byteorder='big')
        )
        unpacked_byte += 2

        # 解析可用性字节
        available_byte = input_payload[unpacked_byte]
        bus_mirror.bus_data[busmirror_message_num].NetworkStateAvailable = 1 if available_byte & 0x80 else 0
        bus_mirror.bus_data[busmirror_message_num].FrameIDAvailable = 1 if available_byte & 0x40 else 0
        bus_mirror.bus_data[busmirror_message_num].PayloadAvailable = 1 if available_byte & 0x80 else 0
        bus_mirror.bus_data[busmirror_message_num].NetworkType = available_byte & 0x1f
        unpacked_byte += 1

        # 解析网络ID和状态
        bus_mirror.bus_data[busmirror_message_num].Netw_ID = input_payload[unpacked_byte]
        unpacked_byte += 1
        bus_mirror.bus_data[busmirror_message_num].Netw_State = input_payload[unpacked_byte]
        unpacked_byte += 1

        if bus_mirror.bus_data[busmirror_message_num].NetworkStateAvailable == 0:
            # 解析有效数据
            bus_mirror.bus_data[busmirror_message_num].FrameID = (
                int.from_bytes(input_payload[unpacked_byte:unpacked_byte + 3], byteorder='big')
            )
            unpacked_byte += 3

            bus_mirror.bus_data[busmirror_message_num].Pay_Length = input_payload[unpacked_byte]
            unpacked_byte += 1

            if bus_mirror.bus_data[busmirror_message_num].Pay_Length > 64:
                print(f"解包数据，mirror_payload.bus_data[{busmirror_message_num}].Pay_Length="
                      f"{bus_mirror.bus_data[busmirror_message_num].Pay_Length},可能存在异常")
                return None


            bus_mirror.bus_data[busmirror_message_num].data = input_payload[unpacked_byte:unpacked_byte+bus_mirror.bus_data[busmirror_message_num].Pay_Length]
            unpacked_byte += bus_mirror.bus_data[busmirror_message_num].Pay_Length
            busmirror_message_num += 1

            if unpacked_byte == bus_mirror.DataLength + offset + 2:
                bus_mirror.bus_data_num = busmirror_message_num
                return bus_mirror
            elif unpacked_byte > bus_mirror.DataLength + offset + 2:
                return None

        else:  # 无效数据
            bus_mirror.bus_data[busmirror_message_num].Pay_Length = 0
            busmirror_message_num += 1

            if unpacked_byte == bus_mirror.DataLength + offset + 2:
                bus_mirror.bus_data_num = busmirror_message_num
                return bus_mirror
            elif unpacked_byte > bus_mirror.DataLength + offset + 2:
                return None

        if unpacked_byte >= input_payload_length:
            return None
