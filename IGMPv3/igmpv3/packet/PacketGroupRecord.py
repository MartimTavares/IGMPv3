# Coded in 2022 by Martim Tavares and Sebastião Limbert, Instituto Superior Técnico.*
# This file is part of the IGMPv3 protocol's development project oriented for a     *
# college engineering course on telecommunications and software engineering.        *
# The date of last update on this file: 9th april 2022                              *

import struct
import socket
from abc import ABCMeta, abstractstaticmethod

from .PacketIGMPMSourceAddress import PacketIGMPMSourceAddress
#How to create an instance of the object:
#address1 = "127.0.0.1"
#g1 = PacketGroupRecord("MODE_IS_INCLUDE", address1)

class PacketGroupRecord:
    """
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Multicast Address                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address [1]                      |
    +-                                                             -+
    |                       Source Address [2]                      |
    +-                                                             -+
    .                               .                               .
    .                               .                               .
    .                               .                               .
    +-                                                             -+
    |                       Source Address [N]                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    .                                                               .
    .                         Auxiliary Data                        .
    .                                                               .
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    GROUP_RECORD = "! BB H 4s"
    GROUP_RECORD_LEN = struct.calcsize(GROUP_RECORD)

    #Access element by returning for example: PacketGroupRecord.RECORD_MSG_TYPES["2"] to get output MODE_IS_EXCLUDE
    RECORD_MSG_TYPES = {"1": "MODE_IS_INCLUDE",
                        "2": "MODE_IS_EXCLUDE",
                        "3": "CHANGE_TO_INCLUDE_MODE",
                        "4": "CHANGE_TO_EXCLUDE_MODE",
                        "5": "ALLOW_NEW_SOURCES",
                        "6": "BLOCK_OLD_SOURCES"}

    def __init__(self, record_type, multicast_address):
        #Checks if the group address is one of two types possible: Bytes or string
        if type(multicast_address) not in (str, bytes):
            raise Exception
        if type(multicast_address) is bytes:
            multicast_address = socket.inet_ntoa(multicast_address)
        contr = False
        for key in PacketGroupRecord.RECORD_MSG_TYPES:
            if record_type == PacketGroupRecord.RECORD_MSG_TYPES[key]:
                contr = True
                break
        if contr == False:
            raise Exception

        self.source_addresses = []
        self.record_type = record_type
        #[RFC:3376] The protocol specified in this document,
        #IGMPv3, does not define any auxiliary data. Therefore,
        #implementations of IGMPv3 MUST NOT include any auxiliary data 
        self.aux_data = 0
        self.multicast_address = multicast_address
    

    def getRecordType(self):
        return self.record_type
    
    
    def getMulticastAddress(self):
        return self.multicast_address


    def addSourceAddress(self, source: PacketIGMPMSourceAddress):
        isAlready = False
        for i in self.source_addresses:
            if i == source:
                isAlready = True
                break
        if isAlready == False:
            self.source_addresses.append(source)


    def bytes(self) -> bytes:
        """
        Obtain packet in byte format
        """
        for key in PacketGroupRecord.RECORD_MSG_TYPES:
            if self.record_type == PacketGroupRecord.RECORD_MSG_TYPES[key]:
                type = int(key)
                
        msg = struct.pack(PacketGroupRecord.GROUP_RECORD, type, 0, len(self.source_addresses), socket.inet_aton(self.multicast_address))
        
        for source in self.source_addresses:
            msg += source.bytes()

        return msg


    @staticmethod
    def parse_bytes(data: bytes):
        """
        From bytes parse and obtain the IGMP Header object and all its payload
        """
        #Filter the data to get only the IGMP Query header
        header = data[0:PacketGroupRecord.GROUP_RECORD_LEN]
        (type, aux_data_len, number_of_sources, multicast_address) = struct.unpack(PacketGroupRecord.GROUP_RECORD, header)
        
        for key in PacketGroupRecord.RECORD_MSG_TYPES:
            if str(type) == key:
                record_type = PacketGroupRecord.RECORD_MSG_TYPES[key]
                
        multicast_address = socket.inet_ntoa(multicast_address)

        packet = PacketGroupRecord(record_type, multicast_address)

        header = data[PacketGroupRecord.GROUP_RECORD_LEN:]
        for i in range(0, number_of_sources):
            source = header[:PacketIGMPMSourceAddress.SOURCE_ADDRESS_LEN]
            auxUnPack = struct.unpack(PacketIGMPMSourceAddress.SOURCE_ADDRESS, source)
            address = PacketIGMPMSourceAddress.parse_bytes(auxUnPack[0])
            packet.addSourceAddress(address)
            header = header[PacketIGMPMSourceAddress.SOURCE_ADDRESS_LEN:]
        return packet


