import socket
import struct
from PacketGroupRecord import PacketGroupRecord
from PacketIGMPv3HeaderQuery import PacketIGMPv3HeaderQuery
from PacketIGMPv3HeaderReport import PacketIGMPv3HeaderReport
from PacketPayload import PacketPayload
#from igmpv3.utils import checksum


class PacketIGMPHeader(PacketPayload):
    '''
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Type     | Max Resp Time |           Checksum            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''

    IGMP_VERSION = 3

    IGMP_HDR = "! BB H"
    IGMP_HDR_LEN = struct.calcsize(IGMP_HDR)

    IGMP_MSG_TYPES = {0x11: PacketIGMPv3HeaderQuery,
                      0x22: PacketIGMPv3HeaderReport,
                      #0x12: PacketIGMPv1Report,
                      #0x16: PacketIGMPv2Report,
                      #0x17: PacketIGMPv2LeaveGroup
                      }


    def __init__(self, payload):
        self.payload = payload
    

    def getIgmpType(self):
        """
        Get IGMP type of packet
        """
        return self.payload.IGMP_TYPE
    

    def getIgmpMaxTime(self):
        """
        Get IGMP max response code of packet
        """
        return self.payload.MAX_TIME


    def bytes(self) -> bytes:
        msg_without_checksum = struct.pack(PacketIGMPHeader.IGMP_HDR, self.getIgmpType(), self.getIgmpMaxTime(), 0)
        msg_without_checksum += self.payload.bytes()
        igmp_checksum = checksum(msg_without_checksum)
        msg = msg_without_checksum[0:2] + struct.pack("! H", igmp_checksum) + msg_without_checksum[4:]
        return msg

    def __len__(self):
        return len(self.bytes())


    @staticmethod
    def parse_bytes(data: bytes):
        print("parseIGMPHdr: ", data)

        header = data[0:PacketIGMPHeader.IGMP_HDR_LEN]
        (type, maxTime, rcv_checksum) = struct.unpack(PacketIGMPHeader.IGMP_HDR, header)

        msg_to_checksum = data[0:2] + b'\x00\x00' + data[4:]
        if checksum(msg_to_checksum) != rcv_checksum:
            print("[ERROR]: Wrong Checksum. The packet may be damaged.")
            print("[ERROR-INFO]: Checksum calculated at destination: " + str(checksum(msg_to_checksum)))
            print("[ERROR-INFO]: Checksum parameter received: " + str(rcv_checksum))
            raise Exception
        
        type_ok = False
        for key in PacketIGMPHeader.IGMP_MSG_TYPES:
            if type == key:
                type_ok = True
        if type_ok == False:
            print("[ERROR]: Wrong message type.")
            print("[ERROR-INFO]: The packet does not correspond to an IGMP packet")
            print("[ERROR-INFO]: Type parameter received: " + str(type))
            raise Exception

        #STILL NEED TO USE MAX TIME FROM PAYLOAD igmp_payload = PacketIGMPHeader.IGMP_MSG_TYPES[type].IGMP_MAX_TIME[maxTime].parse_bytes(igmp_payload)
        igmp_payload = data[PacketIGMPHeader.IGMP_HDR_LEN:]
        igmp_payload = PacketIGMPHeader.IGMP_MSG_TYPES[type].parse_bytes(igmp_payload)
        return PacketIGMPHeader(igmp_payload)



    
report = PacketIGMPv3HeaderReport(0b1010010100001111)
gr1 = PacketGroupRecord("CHANGE_TO_INCLUDE_MODE", "127.0.0.1")
gr2 = PacketGroupRecord("BLOCK_OLD_SOURCES", "224.0.0.1")
report.addGroupRecord(gr1)
report.addGroupRecord(gr2)
print(0x22)
print(report.IGMP_TYPE)

header = PacketIGMPHeader(report)
c = header.bytes()
a = PacketIGMPHeader.parse_bytes(c)
print(a.getIgmpMaxTime())
print(a.getIgmpType())
