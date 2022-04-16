# Coded in 2022 by Martim Tavares and Sebastião Limbert, Instituto Superior Técnico.*
# This file is part of the IGMPv3 protocol's development project oriented for a     *
# college engineering course on telecommunications and software engineering.        *
# The date of last update on this file: 8th april 2022                              *

from audioop import add
import struct
import socket


class PacketIGMPMSourceAddress:

    """
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Source Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    SOURCE_ADDRESS = "! 4s"
    SOURCE_ADDRESS_LEN = struct.calcsize(SOURCE_ADDRESS)

    def __init__(self, source_address: str or bytes):
        if type(source_address) not in (str, bytes):
            raise Exception
        elif type(source_address) is bytes:
            source_address = socket.inet_ntoa(source_address)
        self.source_address = source_address
    

    def getAddress(self):
        return self.source_address

        
    def bytes(self) -> bytes:
        msg = struct.pack(PacketIGMPMSourceAddress.SOURCE_ADDRESS, socket.inet_aton(self.source_address))
        return msg
    

    @staticmethod
    def parse_bytes(data: bytes):
        header = data[0:PacketIGMPMSourceAddress.SOURCE_ADDRESS_LEN]
        address = struct.unpack(PacketIGMPMSourceAddress.SOURCE_ADDRESS, header)
        address = socket.inet_ntoa(address[0])
        packet = PacketIGMPMSourceAddress(address)
        return packet



