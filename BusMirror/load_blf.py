
import BusmirrorParse
from EthFramParse import IPFramProcessor
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
        return self.obj.mChannel == 3
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
        super().__init__(BL_OBJ_TYPE.BL_OBJ_TYPE_ETHERNET_FRAME)

    def filter(self):
        return bytes(self.obj.mSourceAddress) == mac_str_to_bytes("02:df:53:00:00:20") and bytes(self.obj.mDestinationAddress) == mac_str_to_bytes("02:df:53:00:00:03")

# can_msg = CanMessage()
eth_msg = ethMessage()
reader = BlfReader()
if reader.open("ethlog.blf") is False:
    print("Open Error!")
# reader.enroll(can_msg)
reader.enroll(eth_msg)

processor = IPFramProcessor(timeout=2000000000.0)

while (obj := reader.read_data()) is not None:
    # if obj is can_msg:
        # print('can')
        # print(can_msg.obj.mHeader.mObjectTimeStamp, can_msg.obj.mID, can_msg.obj.mChannel, can_msg.obj.DataBytes[:32].hex(' '))
    if obj is eth_msg:
        print(f"TimeStamp:{eth_msg.obj.mHeader.mObjectTimeStamp} sAddress:{eth_msg.obj.SourceAddressStr}, dAddress:{eth_msg.obj.DestinationAddressStr}, Type:{hex(eth_msg.obj.mType)}\nlength:{eth_msg.obj.mPayLoadLength},payload:{eth_msg.obj.PayLoadBytes[:32].hex(' ')}")
        result = processor.process_frame(eth_msg.obj.mHeader.mObjectTimeStamp, eth_msg.obj.PayLoadBytes)
        if result:
            # 打印处理结果
            for packet in result:
                print("\n处理完整的包:")
                print(f"协议: {packet['protocol']}")
                print(f"源IP: {packet['src_ip']}")
                print(f"目的IP: {packet['dst_ip']}")
                if packet['protocol'] == 'UDP':
                    print(f"UDP源端口: {packet['data']['sport']}")
                    print(f"UDP目的端口: {packet['data']['dport']}")
                    print(f"UDP数据长度: {packet['data']['length']}")
                    print(f"UDP数据前100字节: {packet['data']['payload'][:200]}")
                busmirror_info = BusmirrorParse.unpack_bus_mirror(packet['data']['payload'], len(packet['data']['payload']))

reader.close()