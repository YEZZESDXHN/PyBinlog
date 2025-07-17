from PyBLF.pyBLFLib import *


class CanMessage(BlfObjectWrapper):
    obj: None

    def __init__(self):
        super().__init__(BL_OBJ_TYPE.BL_OBJ_TYPE_CAN_FD_MESSAGE_64)

    def filter(self):
        return self.obj.mChannel == 3
# class ethMessage(BlfObjectWrapper):
#     obj: Optional[VBLEthernetFrame] = None
#
#     def __init__(self):
#         super().__init__(BL_OBJ_TYPE.BL_OBJ_TYPE_ETHERNET_FRAME, sizeof(VBLEthernetFrame), VBLEthernetFrame())
#
#     def filter(self):
#         return True

can_msg = CanMessage()
# eth_msg = ethMessage()
reader = BlfReader()
if reader.open("ethlog.blf") is False:
    print("Open Error!")
reader.enroll(can_msg)
# reader.enroll(eth_msg)
while (obj := reader.read_data()) is not None:
    if obj is can_msg:
        print('can')
        print(can_msg.obj.mHeader.mObjectTimeStamp, can_msg.obj.mID, can_msg.obj.mChannel, can_msg.obj.mData)
    # if obj is eth_msg:
    #     print('eth')
    #     print(eth_msg.obj.mHeader.mObjectTimeStamp, eth_msg.obj.mSourceAddress, eth_msg.obj.mDestinationAddress, eth_msg.obj.mType,eth_msg.obj.mPayLoadLength,eth_msg.obj.mPayLoad)

reader.close()