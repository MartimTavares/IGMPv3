# Coded in 2022 by Martim Tavares and Sebastião Limbert, Instituto Superior Técnico.*
# This file is part of the IGMPv3 protocol's development project oriented for a     *
# college engineering course on telecommunications and software engineering.        *
# The date of last update on this file: 16th april 2022                              *

import struct
import socket
from abc import ABCMeta, abstractstaticmethod
from PacketIGMPMSourceAddress import PacketIGMPMSourceAddress
from PacketGroupRecord import PacketGroupRecord


class PacketIGMPv3HeaderReport:
    """
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Reserved            |  Number of Group Records (M)  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    .                                                               .
    .                        Group Record [1]                       .
    .                                                               .
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                               .                               |
    .                               .                               .
    |                               .                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    .                                                               .
    .                        Group Record [M]                       .
    .                                                               .
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    """

    IGMP_TYPE = 0x22
    MAX_TIME = 10

    IGMP_VERSION = 3

    IGMP_HDR_R = "! H H"
    IGMP_HDR_R_LEN = struct.calcsize(IGMP_HDR_R)

    #The Reserved fields are set to zero on transmission, 
    # and ignored on reception.
    IGMP_MAX_TIME = 0


    def __init__(self, reserved_hexa):
        self.reserved = reserved_hexa
        self.group_records = []
    

    def getReserved(self):
        return self.reserved


    def addGroupRecord(self, group_rec: PacketGroupRecord):
        isAlready = False
        for i in self.group_records:
            if i == group_rec:
                isAlready = True
                break
        if isAlready == False:
            self.group_records.append(group_rec)
    

    def bytes(self) -> bytes:
        """
        Obtain packet in byte format
        """
        msg = struct.pack(PacketIGMPv3HeaderReport.IGMP_HDR_R, self.reserved, len(self.group_records))
        
        for group in self.group_records:
            msg += group.bytes()
            
        return msg


    @staticmethod
    def parse_bytes(data: bytes):
        """
        From bytes parse and obtain the IGMP Header object and all its payload
        """
        #Filter the data to get only the IGMP Report header
        header = data[0:PacketIGMPv3HeaderReport.IGMP_HDR_R_LEN]
        (reserved, number_groups) = struct.unpack(PacketIGMPv3HeaderReport.IGMP_HDR_R, header)

        packet = PacketIGMPv3HeaderReport(reserved)

        header = data[PacketIGMPv3HeaderReport.IGMP_HDR_R_LEN:]
        for i in range(0, number_groups):
            group = header[:PacketGroupRecord.GROUP_RECORD_LEN]
            
            group = PacketGroupRecord.parse_bytes(group)
            packet.addGroupRecord(group)
            header = header[PacketGroupRecord.GROUP_RECORD_LEN:]
        return packet




    