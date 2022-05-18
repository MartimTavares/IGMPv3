
from ipaddress import IPv4Address
from threading import Timer
from threading import Lock
import logging
import threading
from igmpv3 import packet
from igmpv3.packet.PacketIGMPHeader import PacketIGMPHeader

from igmpv3.packet.PacketIGMPv3HeaderQuery import PacketIGMPv3HeaderQuery

from . import igmp_globals
from .RouterState import RouterState
from igmpv3.InterfaceIGMP import InterfaceIGMP
from igmpv3.packet.PacketIGMPMSourceAddress import PacketIGMPMSourceAddress
class GroupState:
    # Key: GroupIPAddress, Value: GroupState object
    # In RouterState.py --> self.group_state = {}

    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"

    def __init__(self, mc_ip_address, filter_mode, router_state: RouterState):
        if not IPv4Address(mc_ip_address).is_multicast:
            raise ValueError(mc_ip_address + ' is not a multicast address')
        self.group_ip = mc_ip_address
        # lock
        self.lock = Lock()
        self.set_group_timer()
        self.filter_mode = filter_mode
        # Key: str ip_address, Value: Timer object
        self.source_addresses = {}
        self.router_state = router_state
        self.sources_in_risk_to_exclude = []

    def add_sources(self, source: str):
        isAlready = False
        for i in self.source_addresses:
            if i == source:
                isAlready = True
                break
        if isAlready == False:
            self.set_source_timer(source)

    #          #         #      */
    # TIMERS   #         #      */
    #          #         #      */
    def set_group_timer(self):
        """
        Set back to 0 the group timer
        """
        self.clear_group_timer()
        group_timer = Timer(
            igmp_globals.GROUP_MEMBERSHIP_INTERVAL, self.group_timeout)
        group_timer.start()
        self.group_timer = group_timer

    def clear_group_timer(self):
        """
        Stop group timer
        """
        if self.group_timer is not None:
            self.group_timer.cancel()
    
    def set_source_timer(self, source):
        """
        Set back to 0 the source timer
        """
        self.clear_source_timer(source)
        source_timer = Timer(
            igmp_globals.GROUP_MEMBERSHIP_INTERVAL, self.source_timeout)
        source_timer.start()
        self.source_addresses[source] = source_timer

    def clear_source_timer(self, source):
        """
        Stop source timer
        """
        if self.source_addresses[source] is not None:
            self.source_addresses[source].cancel()

    def group_timeout(self):
        for source in self.sources_in_risk_to_exclude:
            if source in self.source_addresses:
                self.source_addresses.pop(source)
                self.sources_in_risk_to_exclude.pop(source)
        if len(self.source_addresses) == 0:
            self.filter_mode = GroupState.INCLUDE
        

    def source_timeout(self, source: str):
        if self.filter_mode == GroupState.INCLUDE:
            #concludes that traffic from this source is no longer desired
            self.source_addresses.pop(source)
            print("Source {} was removed from group {} sources list.".format(source, self.group_ip))
        elif self.filter_mode == GroupState.EXCLUDE:
            self.source_addresses[source] = None
            if source not in self.sources_in_risk_to_exclude:
                self.sources_in_risk_to_exclude.append(source)
            print("Source {} will be removed if the group timer expires.". format(source))

    #          #         #      */
    # REPORT METHODS     #      */
    #          #         #      */
    def receive_v3_membership_report(self, source_addresses, operation_type):
        lst_ip = []
        for source in source_addresses:
            lst_ip.append(source.getAddress())
        src_ip = []
        for source in self.source_addresses:
            lst_ip.append(source)
        
        #INCLUDE
        if operation_type == 1: 
            if self.filter_mode == GroupState.INCLUDE:
                for s in source_addresses:
                    if s.getAddress() not in self.source_addresses:
                        self.add_sources(s.getAddress())
        #EXCLUDE
        elif operation_type == 2: 
            if len(source_addresses) == 0:
                # EXCLUDE {}
                for s in self.source_addresses:
                    self.source_addresses.pop(s)
            else:
                if self.filter_mode == GroupState.INCLUDE:
                    # EXCLUDE list minus what is common in both lists
                    lst3 = [value for value in src_ip if value in lst_ip]
                    load = list(set(lst_ip) - set(lst3))
                elif self.filter_mode == GroupState.EXCLUDE:
                    load = list(set([value for value in src_ip if value in lst_ip]))

                self.source_addresses = {}
                for s in load:
                    self.add_sources(s)
            self.filter_mode = GroupState.EXCLUDE
        # CHANGE_TO_INCLUDE
        elif operation_type == 3:  
            if self.filter_mode == GroupState.INCLUDE:
                for s in source_addresses:
                    self.add_sources(s)
                #send a group and source specific query Q(G, A-B)
                data = PacketIGMPv3HeaderQuery(0, 0, 2, 125, self.group_ip)
                lst3 = [value for value in src_ip if value in lst_ip]
                load = list(set(lst_ip) - set(lst3))
                for s in load:
                    source = PacketIGMPMSourceAddress(s)
                    data.addSourceAddress(source)
                    self.sources_in_risk_to_exclude.append(s)
                packet = PacketIGMPHeader(data)
                self.router_state.interface.send(packet.bytes(), self.group_ip)
                self.set_group_timer()
                self.filter_mode == GroupState.EXCLUDE
        # CHANGE_TO_EXCLUDE
        elif operation_type == 4:
            # remove the intersection of both source lists from group state
            lst3 = [value for value in src_ip if value in lst_ip]
            load = list(set(lst_ip) - set(lst3))
            for s in self.source_addresses:
                if s in load:
                    self.source_addresses.pop(s)
            #send a group and source specific query Q(G, A-B)
            data = PacketIGMPv3HeaderQuery(0, 0, 2, 125, self.group_ip)
            for s in list(set(lst3)): # common sources
                source = PacketIGMPMSourceAddress(s)
                data.addSourceAddress(source)
            packet = PacketIGMPHeader(data)
            self.router_state.interface.send(packet.bytes(), self.group_ip)
            self.set_group_timer()
            if self.filter_mode == GroupState.INCLUDE:
                self.filter_mode == GroupState.EXCLUDE
        # ALLOW_NEW_SOURCES
        #elif operation_type == 5:  
        #elif operation_type == 6:  # BLOCK_OLD_SOURCES
    
    #          #         #      */
    # QUERY METHODS      #      */
    #          #         #      */

    def receive_group_specific_query(self, max_response_time, source_adds):
        self.set_group_timer()
        # TODO waits until it receives a report in which it is desired to receive from this group
    
    def remove(self):
        self.clear_group_timer
        for source in self.source_addresses:
            self.clear_source_timer(source)
            self.source_addresses.pop(source)



