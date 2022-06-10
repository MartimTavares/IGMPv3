# SETUP
# cp /hosthome/Desktop/IST/Ano_3/ProjInt-IGMPv3/IGMPv3/Router/igmpv3/ . -r
# cd igmpv3/

from packet.PacketIGMPMSourceAddress import PacketIGMPMSourceAddress
from packet.PacketIGMPHeader import PacketIGMPHeader
from packet.PacketIGMPv3HeaderQuery import PacketIGMPv3HeaderQuery
from InterfaceIGMP import InterfaceIGMP
import netifaces
import time

print("Starting interface")
print(netifaces.interfaces())
interface = InterfaceIGMP("eth0", 0)

print("Interface IP: {}".format(interface.get_ip()))

packet = PacketIGMPv3HeaderQuery(0, 0, 2, 125, "224.2.0.10")
source_1 = PacketIGMPMSourceAddress("193.54.0.8")
packet.addSourceAddress(source_1)
igmp_pckt = PacketIGMPHeader(packet)
interface.send(igmp_pckt.bytes(), "224.0.0.1")

i=0
while True:
    time.sleep(10)
    