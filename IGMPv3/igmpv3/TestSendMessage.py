
# SETUP
# cp /hosthome/Desktop/IST/Ano_3/ProjInt-IGMPv3/IGMPv3/IGMPv3/igmpv3/ . -r
# cd igmpv3/

from packet.PacketIGMPMSourceAddress import PacketIGMPMSourceAddress
from packet.PacketIGMPv3HeaderQuery import PacketIGMPv3HeaderQuery
from InterfaceIGMP import InterfaceIGMP
import netifaces


print("Starting interface")
print(netifaces.interfaces())
interface = InterfaceIGMP("eth0", 0)

print("Interface IP: {}".format(interface.get_ip()))
packet = PacketIGMPv3HeaderQuery(0, 0, 2, 125, "223.0.4.1")
source_1 = PacketIGMPMSourceAddress("192.3.34.1")
source_2 = PacketIGMPMSourceAddress("192.3.34.2")
print("Message to send: ")

print("     0                   1                   2                   3")
print("     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1")
print("    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
print("    |                 Group Address: {}                      |".format(packet.getGroupAddress()))
print("    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
pkt_to_bytes = packet.bytes()
interface.send(pkt_to_bytes, "10.0.0.1")
