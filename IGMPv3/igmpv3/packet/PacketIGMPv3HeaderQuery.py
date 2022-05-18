# Coded in 2022 by Martim Tavares and Sebastião Limbert, Instituto Superior Técnico.*
# This file is part of the IGMPv3 protocol's development project oriented for a     *
# college engineering course on telecommunications and software engineering.        *
# The date of last update on this file: 8th april 2022                              *


import struct
import socket
from abc import ABCMeta, abstractstaticmethod
from .PacketIGMPMSourceAddress import PacketIGMPMSourceAddress


class PacketIGMPv3HeaderQuery:
    """
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Group Address                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address [1]                      |
    +-                                                             -+
    |                       Source Address [2]                      |
    +-                              .                              -+
    .                               .                               .
    .                               .                               .
    +-                                                             -+
    |                       Source Address [N]                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    IGMP_TYPE = 0x11
    #Maximum response time is 10 by default
    MAX_TIME = 10

    GROUP_ADDRESS = "0.0.0.0"

    IGMP_VERSION = 3

    IGMP_HDR_Q = "! 4s BB H"
    IGMP_HDR_Q_LEN = struct.calcsize(IGMP_HDR_Q)

    SOURCE = "! 4s"
    SOURCE_LEN = struct.calcsize(SOURCE)


    def __init__(self, resv, s, qrv, qqic, group_address):
        #Checks if the group address is one of two types possible: Bytes or string
        if type(group_address) not in (str, bytes):
            raise Exception
        if type(group_address) is bytes:
            group_address = socket.inet_ntoa(group_address)
        #Initializes an empty list that will contain all the source addresses refered in the message
        #And is of type: PacketIGMPMSourceAddress
        self.source_addresses = []
        self.group_address = group_address
        PacketIGMPv3HeaderQuery.GROUP_ADDRESS = group_address

        self.qqic = qqic
        # Periodic time that the Querier will send queries
        PacketIGMPv3HeaderQuery.MAX_TIME = qqic
        self.qrv = qrv
        self.s = s
        self.resv = resv

    
    def getRESV(self):
        return self.resv
    
    
    def getS(self):
        return self.s
    
    
    def getQRV(self):
        return self.qrv
    
    
    def getQQIC(self):
        return self.qqic
    
    
    def getGroupAddress(self):
        return self.group_address


    def addSourceAddress(self, source: PacketIGMPMSourceAddress):
        isAlready = False
        for i in self.source_addresses:
            if i == source:
                isAlready = True
                break
        if isAlready == False:
            self.source_addresses.append(source)

    def getSourceAddresses(self):
        return self.source_addresses
        

    def bytes(self) -> bytes:
        """
        Obtain packet in byte format
        """
        #example of input: self.resv = 0b10101001
        aux1 = self.resv << 4
        aux2 = self.s << 3
        resvSQrv = aux1 + aux2 + self.qrv

        msg = struct.pack(PacketIGMPv3HeaderQuery.IGMP_HDR_Q, socket.inet_aton(self.group_address), resvSQrv, self.qqic, len(self.source_addresses))
        for source in self.source_addresses:
            msg += source.bytes()
        
        return msg


    @staticmethod
    def parse_bytes(data: bytes):
        """
        From bytes parse and obtain the IGMP Header object and all its payload
        """
        #Filter the data to get only the IGMP Query header
        header = data[0:PacketIGMPv3HeaderQuery.IGMP_HDR_Q_LEN]
        (group_address, resvSQrv, qqic, total_sources) = struct.unpack(PacketIGMPv3HeaderQuery.IGMP_HDR_Q, header)
        """
        'GROUP ADDRESS': socket.inet_ntoa(group_address), 
        'RESV': resv,
        'S': s,
        'QRV': qrv, 
        'QQIC': qqic, 
        'SOURCES': totalSources
        """
        resv = (resvSQrv & 0xF0) >> 4
        s = (resvSQrv & 0x08) >> 3
        qrv = (resvSQrv & 0x07)
        group_address = socket.inet_ntoa(group_address)

        packet = PacketIGMPv3HeaderQuery(resv, s, qrv, qqic, group_address)

        header = data[PacketIGMPv3HeaderQuery.IGMP_HDR_Q_LEN:]
        for i in range(0, total_sources):
            source = header[:PacketIGMPv3HeaderQuery.SOURCE_LEN]
            auxUnPack = struct.unpack(PacketIGMPv3HeaderQuery.SOURCE, source)
            address = PacketIGMPMSourceAddress.parse_bytes(auxUnPack[0])
            packet.addSourceAddress(address)
            header = header[PacketIGMPv3HeaderQuery.SOURCE_LEN:]
        return packet

