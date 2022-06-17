
from packet.PacketIGMPv3HeaderReport import PacketIGMPv3HeaderReport
from packet.PacketGroupRecord import PacketGroupRecord
from packet.PacketIGMPMSourceAddress import PacketIGMPMSourceAddress
from packet.PacketIGMPHeader import PacketIGMPHeader
import socket
import netifaces


def chooseInterface():
    interfaces = netifaces.interfaces()

    def printInterfaces():
        print('Choose the network interface:')
        for i in range(len(interfaces)):
            print(i+1, '-', interfaces[i])

    if len(interfaces) == 1:  # user has just 1 interface and any
        return interfaces[0]
    else:
        printInterfaces()
        inputValue = input('Interface number: ')

        if int(inputValue)-1 not in range(len(interfaces)):
            raise Exception('Invalid interface number')
        inputValue = interfaces[int(inputValue)-1]
        return inputValue

# SEND SOCKET
snd_s = socket.socket(
    socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)

# bind to interface
snd_s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                 str("eth0" + "\0").encode('utf-8'))


packet = PacketIGMPv3HeaderReport(0)

#rec_2 = PacketGroupRecord(1, "224.4.0.8")
#rec_3 = PacketGroupRecord(3, "224.4.0.9")
#src_2 = PacketIGMPMSourceAddress("193.1.91.2")

#rec_1.addSourceAddress(src_2)

#packet.addGroupRecord(rec_2)
#packet.addGroupRecord(rec_3)






print("[1] Send a CHANGE_TO_EXCLUDE")
while True:
    action = input("Give a number: ")
    if int(action) == 1:
        print("Selected [1]")
        rec_1 = PacketGroupRecord(4, "224.6.0.1")
        src = PacketIGMPMSourceAddress("193.1.91.1")
        rec_1.addSourceAddress(src)
        packet.addGroupRecord(rec_1)
        print("CHANGE_TO_EXCLUDE; 224.6.0.1; 193.1.91.1(source)")
        data = PacketIGMPHeader(packet)
        data = data.bytes()
        print(data)
        snd_s.sendto(data, ("10.0.0.1", 0))
