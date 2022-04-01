import socket
import struct
from igmpv3.packet.PacketPayload import PacketPayload
from igmpv3.utils import checksum


class PacketIGMPHeader(PacketPayload):
    '''
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Type     | Max Resp Time |           Checksum            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''

    IGMP_TYPE = 3

    IGMP_HDR_1 = "! BB H"
    IGMP_HDR_1_LEN = struct.calcsize(IGMP_HDR_1)

    #IGMP3_SRC_ADDR_HDR = "! BB H "
    #IGMP3_SRC_ADDR_HDR_LEN = struct.calcsize(IGMP3_SRC_ADDR_HDR)

    #IPv4_HDR = "! 4s"
    #IPv4_HDR_LEN = struct.calcsize(IPv4_HDR)

    MEMBERSHIP_QUERY = 0x11
    VERSION_3_MEMBERSHIP_REPORT = 0x22
    
    #MUST SUPPORT OLDER VERSIONS
    VERSION_1_MEMBERSHIP_REPORT = 0x12
    VERSION_2_MEMBERSHIP_REPORT = 0x16
    VERSION_2_LEAVE_GROUP = 0x17

    def __init__(self, typeMessage: int, maxResponseTime: int):
        self.type = typeMessage
        self.maxResponseTime = maxResponseTime
    

    def getIgmpType(self):
        """
        Get IGMP type of packet
        """
        return self.type
    
    def getIgmpMaxTime(self):
        """
        Get IGMP max response code of packet
        """
        return self.maxResponseTime


class PacketIGMPHeaderQuery(PacketIGMPHeader):
    '''
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Type     | Max Resp Code |           Checksum            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Group Adress                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Resv |S| QRV |     QQIC      |    Number of Sources (N)      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''

    IGMP_HDR_Q = "! BB H 4s BB H"
    IGMP_HDR_Q_LEN = struct.calcsize(IGMP_HDR_Q)

    def __init__(self, typeMessage: int, maxResponseTime: int, resv: int, s: int, qrv: int, qqic: int, numberOfSources: int, groupIP: str = "0.0.0.0"):
        super().__init__(typeMessage, maxResponseTime)
        self.groupAddress = groupIP
        self.resv = resv
        self.s = s
        self.qrv = qrv
        self.qqic = qqic
        self.numberOfSources = numberOfSources

    def getIgmpType(self):
        """
        Get IGMP type of packet
        """
        return super().getIgmpMaxTime()

    def getMaxCode(self):
        """
        Get IGMP max time code
        """
        return super().getIgmpMaxTime()

    #------------------------------- Turning packet into a bus of bytes -------------------------------
    #------------------------------- and turning bytes into data object -------------------------------
    
    def bytes(self) -> bytes:
        """
        Obtain packet in byte format
        """
        #example of input: self.resv = 0b10101001
        aux1 = self.resv << 4
        aux2 = self.s << 3
        resvSQrv = aux1 + aux2 + self.qrv
        
        
        # get the message and obtain its checksum 
        msgWithoutChecksum = struct.pack(PacketIGMPHeaderQuery.IGMP_HDR_Q, self.getIgmpType(), self.getIgmpMaxTime, 0,
                                          socket.inet_aton(self.groupAddress), resvSQrv, self.qqic, self.numberOfSources)
        igmpChecksum = checksum(msgWithoutChecksum)
        msg = msgWithoutChecksum[0:2] + struct.pack("! H", igmpChecksum) + msgWithoutChecksum[4:]
        return msg
    
    def __len__(self):
        return len(self.bytes())
    
    @staticmethod
    def parse_bytes(data: bytes):
        """
        From bytes parse and obtain the IGMP Header object and all its payload
        """
        #Filter the data to get only the IGMP Query header
        header = data[0:PacketIGMPHeaderQuery.IGMP_HDR_Q_LEN]
        (type, maxTime, rcvChecksum, groupAddress, resvSQrv, qqic, totalSources) = struct.unpack(PacketIGMPHeaderQuery.IGMP_HDR_Q, header)

        #Checking if the packet contains the entire message through the checksum option
        msgToChecksum = data[0:2] + b'\x00\x00' + data[4:]
        if checksum(msgToChecksum) != rcvChecksum:
            #print("wrong checksum")
            raise Exception("[ERROR]: Wrong Checksum. The packet may be damaged.")

        """
        'TYPE': type,
        'MAXRESPTIME': maxTime, 
        'CHECKSUM': rcvChecksum, 
        'GROUPADDRESS': socket.inet_ntoa(groupAddress), 
        'RESV': resv,
        'S': s,
        'QRV': qrv, 
        'QQIC': qqic, 
        'SOURCES': totalSources
        """

        resv = (resvSQrv & 0xF0) >> 4
        s = (resvSQrv & 0x08) >> 3
        qrv = (resvSQrv & 0x07)

        groupAddress = socket.inet_ntoa(groupAddress)
        
        packet = PacketIGMPHeaderQuery(type, maxTime, resv, s, qrv, qqic, totalSources, groupAddress)
        return packet




class PacketIGMPHeaderReport(PacketIGMPHeader):
    
