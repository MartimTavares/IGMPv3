# Coded in 2022 by Martim Tavares and Sebastião Limbert, Instituto Superior Técnico.*
# This file is part of the IGMPv3 protocol's development project oriented for a     *
# college engineering course on telecommunications and software engineering.        *
# The date of last update on this file: 20th april 2022                             *

import struct
import socket
from abc import ABCMeta, abstractstaticmethod


class PacketIGMPv1v2Header:
    """
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Group Address                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    # /* IGMP type can be:                       *
    # /* 0x12: IGMPv1 Membership Report Packet   *
    # /* 0x16: IGMPv2 Membership Report Packet   *
    # /* 0x17: IGMPv2 LeaveGroup Packet          *

    IGMP_V1V2 = "! 4s"
    IGMP_V1V2_LEN = struct.calcsize(IGMP_V1V2)

    IGMP_TYPE = ""

    def __init__(self, group_address):
        #Checks if the group address is one of two types possible: Bytes or string
        if type(group_address) not in (str, bytes):
            raise Exception
        if type(group_address) is bytes:
            group_address = socket.inet_ntoa(group_address)
        self.group_address = group_address
        self.type = 0x0


    def getGroupAddress(self):
        return self.group_address


    def getType(self):
        return self.type
    
    
    def addType(self, type):
        self.type = type
        PacketIGMPv1v2Header.IGMP_TYPE = type


    def bytes(self) -> bytes:
        """
        Obtain packet in byte format
        """
        msg = struct.pack(PacketIGMPv1v2Header.IGMP_V1V2, socket.inet_aton(self.group_address))
        return msg
    

    @staticmethod
    def parse_bytes(data: bytes):
        """
        From bytes parse and obtain the IGMP Header object and all its payload
        """
        #Filter the data to get only the IGMP Query header
        header = data[0:PacketIGMPv1v2Header.IGMP_V1V2_LEN]
        group_address = struct.unpack(PacketIGMPv1v2Header.IGMP_V1V2, header)
        
        group_address = socket.inet_ntoa(group_address[0])

        packet = PacketIGMPv1v2Header(group_address)
        return packet


