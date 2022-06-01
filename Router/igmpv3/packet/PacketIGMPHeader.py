# Coded in 2022 by Martim Tavares, Instituto Superior Técnico.                      *
# This file is part of the IGMPv3 protocol's development project oriented for a     *
# college engineering course on telecommunications and software engineering.        *
# The date of last update on this file: 18th april 2022                             *

import socket
import struct
from .PacketGroupRecord import PacketGroupRecord
from .PacketIGMPv3HeaderQuery import PacketIGMPv3HeaderQuery
from .PacketIGMPv3HeaderReport import PacketIGMPv3HeaderReport
from .PacketIGMPv1v2Header import PacketIGMPv1v2Header
from .PacketPayload import PacketPayload
from .utils import checksum


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
                      "older_versions": PacketIGMPv1v2Header,
                      }
    #  *     0x11: IGMPv3 Packet Header Query        *
    #  *     0x22: IGMPv3 Packet Header Report       *
    #  *     0x12: IGMPv1 Membership Report Packet   *
    #  *     0x16: IGMPv2 Membership Report Packet   *
    #  *     0x17: IGMPv2 LeaveGroup Packet          *

    IGMP_MSG_KEYS = [0x11, 0x22, 0x12, 0x16, 0x17]


    def __init__(self, payload):
        self.payload = payload
    

    def getPayload(self):
        """
        Get IGMP payload
        """
        return self.payload
    
    
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
    
    
    def getMCGroupAdress(self):
        """
        Get Group Address of packet
        """
        if self.payload.IGMP_TYPE == 0x11:
            return self.payload.GROUP_ADDRESS
        else:
            return


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
        #type is an 8 bit data and in v1 and v2 type is the last 3 bits from first byte
        v1_v2_type = (type & 0x07)
        for key in PacketIGMPHeader.IGMP_MSG_KEYS:
            if type == key:
                type_ok = True
                break
            elif v1_v2_type == key:
                #Check if it is a v1 or v2 type message
                type_ok = True
                break

        if type_ok == False:
            print("[ERROR]: Wrong message type.")
            print("[ERROR-INFO]: The packet does not correspond to an IGMP packet")
            print("[ERROR-INFO]: Type parameter received: " + str(type))
            raise Exception

        igmp_payload = data[PacketIGMPHeader.IGMP_HDR_LEN:]
        if (type == 0x11 or type == 0x22):
            igmp_payload = PacketIGMPHeader.IGMP_MSG_TYPES[type].parse_bytes(igmp_payload)
        elif (v1_v2_type == 0x12 or v1_v2_type == 0x16 or v1_v2_type == 0x17):
            igmp_payload = PacketIGMPHeader.IGMP_MSG_TYPES["older_versions"].parse_bytes(igmp_payload)
            igmp_payload.addType(v1_v2_type)

        return PacketIGMPHeader(igmp_payload)



#EXAMPLE OF HEADER'S CODE USAGE:    
#report = PacketIGMPv3HeaderReport(0b1010010100001111)
#gr1 = PacketGroupRecord("CHANGE_TO_INCLUDE_MODE", "127.0.0.1")
#gr2 = PacketGroupRecord("BLOCK_OLD_SOURCES", "224.0.0.1")
#report.addGroupRecord(gr1)
#report.addGroupRecord(gr2)
#print(0x22)
#print(report.IGMP_TYPE)

#header = PacketIGMPHeader(report)
#print(header.payload.bytes())
#c = header.bytes()
#print(c)
#a = PacketIGMPHeader.parse_bytes(c)
#print(a.getIgmpMaxTime())
#print(a.getIgmpType())
