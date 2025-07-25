
import BusmirrorParse
from EthFramParse import IPFramProcessor, PayloadType
from PyBLF.pyBLFLib import *
# from scapy import IP, UDP, defragment



###### write test ########
# can_msg = Create_BL_OBJ_By_Type(BL_OBJ_TYPE.BL_OBJ_TYPE_CAN_MESSAGE)
# writer = BlfWriter()
# can_msg.mHeader.mBase.mSignature = BL_OBJ_TYPE.BL_OBJ_SIGNATURE
# can_msg.mHeader.mBase.mHeaderSize = sizeof(can_msg.mHeader)
# can_msg.mHeader.mBase.mHeaderVersion = 1
# can_msg.mHeader.mBase.mObjectSize = sizeof(can_msg)
# can_msg.mHeader.mBase.mObjectType = BL_OBJ_TYPE.BL_OBJ_TYPE_CAN_MESSAGE
# can_msg.mHeader.mObjectFlags = BL_OBJ_FLAG_IDs.BL_OBJ_FLAG_TIME_ONE_NANS
#
# can_msg.mChannel = 1
# can_msg.mFlags = 0
# can_msg.mDLC = 8
# can_msg.mID = 0x100
# writer.open("write_test.blf")
# writer.set_compression_level(6)
#
# now = datetime.today().timetuple()
# st = SYSTEMTIME()
# st.wYear = now.tm_year
# st.wMonth = now.tm_mon
# st.wDay = now.tm_mday
# st.wDayOfWeek = now.tm_wday
# st.wHour = now.tm_hour-1
# st.wMinute = now.tm_min
# st.wSecond = now.tm_sec
# writer.set_measurement_start_time(st)
#
# for x in range(10):
#     can_msg.mHeader.mObjectTimeStamp = x * 10000000
#     for i in range(8):
#         can_msg.mData[i] = i + x
#     writer.write(can_msg)
#
# writer.close()


########## read test ###########
class CanMessage(BlfObjectWrapper):
    obj: None

    def __init__(self):
        super().__init__(BL_OBJ_TYPE.BL_OBJ_TYPE_CAN_FD_MESSAGE_64)

    def filter(self):
        return self.obj.mChannel == 4
def mac_str_to_bytes(mac_str):
    """
    将MAC地址字符串转换为bytes类型

    Args:
        mac_str: MAC地址字符串，支持格式：
                - "AA:BB:CC:DD:EE:FF"
                - "AA-BB-CC-DD-EE-FF"
                - "AABBCCDDEEFF"

    Returns:
        bytes: MAC地址的bytes表示

    Raises:
        ValueError: 当MAC地址格式无效时抛出
    """
    try:
        # 移除所有分隔符
        mac_str = mac_str.replace(':', '').replace('-', '').replace(' ', '')

        # 检查长度
        if len(mac_str) != 12:
            raise ValueError("MAC address must be 12 hexadecimal characters")

        # 检查是否是有效的十六进制字符
        if not all(c in '0123456789ABCDEFabcdef' for c in mac_str):
            raise ValueError("Invalid characters in MAC address")

        # 转换为bytes
        return bytes.fromhex(mac_str)

    except Exception as e:
        raise ValueError(f"Invalid MAC address format: {e}")
class ethMessage(BlfObjectWrapper):
    obj: None

    def __init__(self):
        # super().__init__(BL_OBJ_TYPE.BL_OBJ_TYPE_ETHERNET_FRAME)
        super().__init__(BL_OBJ_TYPE.BL_OBJ_TYPE_ETHERNET_FRAME)

    def filter(self):
        return bytes(self.obj.mSourceAddress) == mac_str_to_bytes("02:df:53:00:00:20") and bytes(self.obj.mDestinationAddress) == mac_str_to_bytes("02:df:53:00:00:03")


class ethMessage_ex(BlfObjectWrapper):
    obj: None

    def __init__(self):
        # super().__init__(BL_OBJ_TYPE.BL_OBJ_TYPE_ETHERNET_FRAME)
        super().__init__(BL_OBJ_TYPE.BL_OBJ_TYPE_ETHERNET_FRAME_EX)

    def filter(self):
        return True

# can_msg1 = CanMessage()
eth_msg = ethMessage()
eth_msg_ex = ethMessage_ex()
reader = BlfReader()
if reader.open("ML_R410RD7_143_100_TC_0x20010003_to_ivi_autoEasyEntrySet_20250714194334_org.blf") is False:
    print("Open Error!")
# reader.enroll(can_msg1)
reader.enroll(eth_msg)
reader.enroll(eth_msg_ex)

processor = IPFramProcessor(timeout=2000000000.0)

can_msg = Create_BL_OBJ_By_Type(BL_OBJ_TYPE.BL_OBJ_TYPE_CAN_FD_MESSAGE_64)
writer = BlfWriter()
can_msg.mHeader.mBase.mSignature = BL_OBJ_TYPE.BL_OBJ_SIGNATURE
can_msg.mHeader.mBase.mHeaderSize = sizeof(can_msg.mHeader)
can_msg.mHeader.mBase.mHeaderVersion = 1
can_msg.mHeader.mBase.mObjectSize = sizeof(can_msg)
can_msg.mHeader.mBase.mObjectType = BL_OBJ_TYPE.BL_OBJ_TYPE_CAN_FD_MESSAGE_64
can_msg.mHeader.mObjectFlags = BL_OBJ_FLAG_IDs.BL_OBJ_FLAG_TIME_ONE_NANS
#
# can_msg.mChannel = 1
can_msg.mFlags = 3289152
# can_msg.mDLC = 8
# can_msg.mID = 0x100
writer.open("ML_R410RD7_143_100_TC_0x20010003_to_ivi_autoEasyEntrySet_20250714194334_org_parse_busmirror.blf")
writer.set_compression_level(6)
first_flag=0
start_Timestamp=0


while (obj := reader.read_data()) is not None:
    # if obj is can_msg1:
    #     print('can')
    #     print(can_msg1.obj.mHeader.mObjectTimeStamp, can_msg1.obj.mID, can_msg1.obj.mChannel, can_msg1.obj.DataBytes[:32].hex(' '))
    if obj is eth_msg:
        # print(f"TimeStamp:{obj.obj.mHeader.mObjectTimeStamp},length:{obj.obj.PayLoadLength},payload:{obj.obj.PayLoadBytes[:32].hex(' ')}")
        result = processor.process_frame(obj.obj.mHeader.mObjectTimeStamp,
                                         obj.obj.PayLoadBytes,
                                         PayloadType.IP,
                                         sMAC=obj.obj.sMACStr,
                                         dMAC=obj.obj.dMACStr)

    elif obj is eth_msg_ex:
        # print(
        #     f"TimeStamp:{obj.obj.mHeader.mObjectTimeStamp},length:{obj.obj.PayLoadLength},payload:{obj.obj.PayLoadBytes[:32].hex(' ')}")
        result = processor.process_frame(obj.obj.mHeader.mObjectTimeStamp, obj.obj.PayLoadBytes, PayloadType.ETHERNET)
    if result:
        for packet in result:
            if packet.sMAC == "02:df:53:00:00:20" and packet.dMAC == "02:df:53:00:00:03" and packet.PacketType == "UDP" and packet.udp.sPort == 58030:
                busmirror_info = BusmirrorParse.unpack_bus_mirror(packet.udp.payload,packet.udp.length)
                if first_flag == 0:
                    start_Timestamp=busmirror_info.HeaderTimestamp
                    # now = datetime.today().timetuple()
                    # st = SYSTEMTIME()
                    # writer.set_measurement_start_time(st)
                    first_flag=1
                if busmirror_info is not None:
                    for msg in busmirror_info.bus_data:
                        #
                        # mObjectTimeStamp                  1ms = 1 * 1000000
                        # busmirror_info.HeaderTimestamp    1ms = 1 * 1000000
                        # msg.Timestamp                     1ms = 1 * 100
                        #
                        can_msg.mHeader.mObjectTimeStamp = (busmirror_info.HeaderTimestamp - start_Timestamp ) + msg.Timestamp*10000
                        can_msg.mChannel = msg.Netw_ID
                        can_msg.mDLC = msg.Pay_Length
                        can_msg.mID = msg.FrameID
                        for x in range(msg.Pay_Length):
                            can_msg.mData[x]=msg.data[x]
                        writer.write(can_msg)

        # if result:
        #     # 打印处理结果
        #     for packet in result:
        #         # print("\n处理完整的包:")
        #         # print(f"协议: {packet['protocol']}")
        #         # print(f"源IP: {packet['src_ip']}")
        #         # print(f"目的IP: {packet['dst_ip']}")
        #         # if packet['protocol'] == 'UDP':
        #         #     print(f"UDP源端口: {packet['data']['sport']}")
        #         #     print(f"UDP目的端口: {packet['data']['dport']}")
        #         #     print(f"UDP数据长度: {packet['data']['length']}")
        #         #     print(f"UDP数据前100字节: {packet['data']['payload'][:200]}")
        #         if packet['protocol'] == 'UDP' and packet['data']['sport'] == 58030:
        #             busmirror_info = BusmirrorParse.unpack_bus_mirror(packet['data']['payload'], len(packet['data']['payload']))
        #             if first_flag==0:
        #                 start_Timestamp=busmirror_info.HeaderTimestamp
        #                 now = datetime.today().timetuple()
        #                 st = SYSTEMTIME()
        #                 writer.set_measurement_start_time(st)
        #                 first_flag=1
        #             if busmirror_info is not None:
        #                 for msg in busmirror_info.bus_data:
        #                     #
        #                     # mObjectTimeStamp                  1ms = 1 * 1000000
        #                     # busmirror_info.HeaderTimestamp    1ms = 1 * 1000000
        #                     # msg.Timestamp                     1ms = 1 * 100
        #                     #
        #                     can_msg.mHeader.mObjectTimeStamp = (busmirror_info.HeaderTimestamp - start_Timestamp ) + msg.Timestamp*10000
        #                     can_msg.mChannel = msg.Netw_ID
        #                     can_msg.mDLC = msg.Pay_Length
        #                     can_msg.mID = msg.FrameID
        #                     for x in range(msg.Pay_Length):
        #                         can_msg.mData[x]=msg.data[x]
        #                     writer.write(can_msg)
reader.close()
writer.close()