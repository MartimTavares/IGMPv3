from ipaddress import IPv4Address
from threading import Timer
from threading import Lock
import logging
import threading

from packet.PacketIGMPHeader import PacketIGMPHeader
from packet.PacketIGMPv3HeaderQuery import PacketIGMPv3HeaderQuery
from packet.PacketIGMPv3HeaderReport import PacketIGMPv3HeaderReport
from packet.ReceivedPacket import ReceivedPacket
from packet.utils import TYPE_CHECKING

from igmp_globals import QUERY_INTERVAL, OTHER_QUERIER_PRESENT_INTERVAL
from GroupState import GroupState

if TYPE_CHECKING:
    from InterfaceIGMP import InterfaceIGMP


class RouterState(object):
    
    ROUTER_STATE_LOGGER = logging.getLogger('igmp.igmpv3.RouterState')

    def __init__(self, interface: 'InterfaceIGMP'):
        #logger
        logger_extra = dict()
        logger_extra['vif'] = interface.vif_index
        logger_extra['interfacename'] = interface.interface_name
        self.router_state_logger = logging.LoggerAdapter(RouterState.ROUTER_STATE_LOGGER, logger_extra)

        # interface of the router connected to the network
        self.interface = interface

        # state of the router (Querier/NonQuerier)
        self.interface_state = "Querier"
        self.whoIsQuerier = self.interface.get_ip()

        # state of each group
        # Key: GroupIPAddress, Value: GroupState object
        self.group_state = {}
        self.group_state_lock = threading.Lock()

        # send general query to all the routers, where S=0 | qrv=2 | QQIC=125
        packet = PacketIGMPv3HeaderQuery(0, 0, 2, 125, "224.0.0.22")
        igmp_pckt = PacketIGMPHeader(packet)
        self.interface.send(igmp_pckt.bytes(), "224.0.0.22")

        # set initial general query timer 
        timer = Timer(igmp_globals.QUERY_INTERVAL, self.general_query_timeout)
        timer.start()
        self.general_query_timer = timer

        # present timer
        self.other_querier_present_timer = None

    # Send packet via interface
    def send(self, data: bytes, address: str):
        self.interface.send(data, address)

    ############################################
    # interface_state methods
    ############################################

    def set_general_query_timer(self):
        """
        Set back to 0 the general query timer
        """
        self.clear_general_query_timer()
        #means it will wait x time - 1st parameter - and then it will execute the function - 2nd parameter.
        general_query_timer = Timer(igmp_globals.QUERY_INTERVAL, self.general_query_timeout)
        general_query_timer.start()
        self.general_query_timer = general_query_timer

    def clear_general_query_timer(self):
        """
        Stop general query timer
        """
        if self.general_query_timer is not None:
            self.general_query_timer.cancel()

    def set_other_querier_present_timer(self):
        """
        Set back to 0 the other querier present timer
        """
        self.clear_other_querier_present_timer()
        other_querier_present_timer = Timer(igmp_globals.OTHER_QUERIER_PRESENT_INTERVAL, self.other_querier_present_timeout)
        other_querier_present_timer.start()
        self.other_querier_present_timer = other_querier_present_timer

    def clear_other_querier_present_timer(self):
        """
        Stop other querier present timer
        """
        if self.other_querier_present_timer is not None:
            self.other_querier_present_timer.cancel()

    def general_query_timeout(self):
        """
        General Query timer has expired
        """
        self.router_state_logger.debug('State: general_query_timeout')
        #sends a new general query 
        packet = PacketIGMPv3HeaderQuery(0, 0, 2, igmp_globals.QUERY_INTERVAL, "0.0.0.0")
        igmp_pckt = PacketIGMPHeader(packet)
        if self.interface_state == "Querier":
            self.interface.send(igmp_pckt.bytes(), "224.0.0.1")
            self.set_general_query_timer()

    def other_querier_present_timeout(self):
        """
        Other Querier Present timer has expired
        """
        self.router_state_logger.debug('State: other_querier_present_timeout')
        # becomes the Querier
        self.change_interface_state(True)
        self.clear_other_querier_present_timer()
        self.clear_general_query_timer()
        # send general query to all the routers, where S=0 | qrv=2 | QQIC=125
        packet = PacketIGMPv3HeaderQuery(0, 0, 2, 125, "224.0.0.22")
        igmp_pckt = PacketIGMPHeader(packet)
        self.interface.send(igmp_pckt.bytes(), "224.0.0.22")

    def change_interface_state(self, querier: bool):
        """
        Change state regarding querier state machine (Querier/NonQuerier)
        """
        if querier:
            self.interface_state = "Querier"
            self.router_state_logger.debug(
                'change querier state to -> Querier')
        else:
            self.interface_state = "NonQuerier"
            self.router_state_logger.debug(
                'change querier state to -> NonQuerier')

    ############################################
    # group state methods
    ############################################
    def get_group_state(self, group_ip):
        """
        Get object that monitors a given group (with group_ip IP address)
        """
        self.group_state_lock.acquire()
        if group_ip in self.group_state:
            self.group_state_lock.release()
            return self.group_state[group_ip]
        else:
            group_state = GroupState(group_ip,"INCLUDE", self)
            self.group_state[group_ip] = group_state
            self.group_state_lock.release()
            return group_state

    def receive_v3_membership_report(self, packet: ReceivedPacket):
        """
        Received IGMP Membership Report packet
        """
        group_records = packet.payload.getPayload().group_records
        for group in group_records:
            mc_ip = group.getMulticastAddress()
            adds = group.source_addresses  # list of PacketIGMPMSourceAddress
            #e.g: TO_INCLUDE
            fnct = group.getRecordType()
            self.get_group_state(mc_ip).receive_v3_membership_report(adds, fnct)

    def receive_query(self, packet: ReceivedPacket):
        """
        Received IGMP Query packet
        """
        igmp_group = packet.payload.getPayload().getGroupAddress()
        sources = packet.payload.getPayload().getSourceAddresses()
        sFlag = packet.payload.getPayload().getS()
        ip_src = packet.ip_header.ip_src
        # process group specific query
        # expects to receive a report from the hosts of this specific group
        if igmp_group != "0.0.0.0" and igmp_group in self.group_state:
            max_response_time = packet.payload.getIgmpMaxTime()
            self.get_group_state(igmp_group).receive_group_specific_query(
                max_response_time, sources)
            
        # querier election process
        if IPv4Address(ip_src) < IPv4Address(self.interface.get_ip()):
            #Becomes Non-Querier if not already
            self.change_interface_state(False)
            self.clear_other_querier_present_timer()
            self.clear_general_query_timer()
            #Checks if it is a new Querier
            if IPv4Address(ip_src) <= IPv4Address(self.whoIsQuerier):
                self.whoIsQuerier = ip_src
                if sFlag == 0:
                    self.set_other_querier_present_timer()
            

    def remove_group(self, group_ip):
        self.group_state.pop(group_ip)
            

    def remove(self):
        """
        Remove this IGMP interface
        Clear all state
        """
        for group in self.group_state.values():
            group.remove()
        self.clear_general_query_timer()
        self.clear_other_querier_present_timer()
