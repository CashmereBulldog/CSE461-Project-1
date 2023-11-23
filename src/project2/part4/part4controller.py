# Part 4 of UWCSE's Mininet-SDN project
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from collections import defaultdict

log = core.getLogger()

# Convenience mappings of hostnames to ips
IPS = {
    "h10": "10.0.1.10",
    "h20": "10.0.2.20",
    "h30": "10.0.3.30",
    "serv1": "10.0.4.10",
    "hnotrust": "172.16.10.100",
}

# Convenience mappings of hostnames to subnets
SUBNETS = {
    "h10": "10.0.1.0/24",
    "h20": "10.0.2.0/24",
    "h30": "10.0.3.0/24",
    "serv1": "10.0.4.0/24",
    "hnotrust": "172.16.10.0/24",
}


class Part4Controller(object):
    """
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        print(connection.dpid)
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection
        
        ipv6_fm = of.ofp_flow_mod()
        ipv6_fm.match = of.ofp_match(dl_type=0x0886)
        ipv6_fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(ipv6_fm)
        
        # Table for storing MAC to ports
        self.ip_to_port = defaultdict(int)
        self.port_to_mac = {}

        # This binds our PacketIn event listener
        connection.addListeners(self)
        # use the dpid to figure out what switch is being created
        if connection.dpid == 1:
            self.s1_setup()
        elif connection.dpid == 2:
            self.s2_setup()
        elif connection.dpid == 3:
            self.s3_setup()
        elif connection.dpid == 21:
            self.cores21_setup()
        elif connection.dpid == 31:
            self.dcs31_setup()
        else:
            print("UNKNOWN SWITCH")
            exit(1)

    def s1_setup(self):
        fm = of.ofp_flow_mod()
        fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(fm)

    def s2_setup(self):
        fm = of.ofp_flow_mod()
        fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(fm)

    def s3_setup(self):
        fm = of.ofp_flow_mod()
        fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(fm)

    def cores21_setup(self):
        notrust_fm = of.ofp_flow_mod()
        notrust_fm.match = of.ofp_match(dl_type=0x0800)
        notrust_fm.match.nw_proto = 1
        notrust_fm.match.nw_src = SUBNETS["hnotrust"]
        notrust_fm.actions.append(of.ofp_action_output(port=0))
        self.connection.send(notrust_fm)

    def dcs31_setup(self):
        notrust_fm = of.ofp_flow_mod()
        notrust_fm.match = of.ofp_match(dl_type=0x0800)
        notrust_fm.match.nw_src = SUBNETS["hnotrust"]
        notrust_fm.actions.append(of.ofp_action_output(port=0))
        self.connection.send(notrust_fm)

        fm = of.ofp_flow_mod()
        fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(fm)

    # used in part 4 to handle individual ARP packets
    # not needed for part 3 (USE RULES!)
    # causes the switch to output packet_in on out_port
    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def _handle_PacketIn(self, event):
        """
        Packets not handled by the router rules will be
        forwarded to this method to be handled by the controller
        """

        packet = event.parsed  # This is the parsed packet data.
        if packet.type == packet.IPV6_TYPE:
            return
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.
        print(
            "Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump()
        )

        src_ip, dst_ip = "", ""

        if not packet.type == packet.ARP_TYPE:
            # Get the ip address information
            ip_packet = packet.payload
            src_ip = ip_packet.srcip
            dst_ip = ip_packet.dstip
        else:
            # Write arp reply if the packet was an arp request
            arp_reply = arp()
            arp_reply.hwsrc = EthAddr('de:ad:be:ef:ca:fe')
            arp_reply.hwdst = packet.src
            arp_reply.opcode = arp.REPLY
            arp_reply.protosrc = packet.payload.protodst
            arp_reply.protodst = packet.payload.protosrc
            src_ip = packet.payload.protosrc
            dst_ip = packet.payload.protodst
            ether = ethernet()
            ether.type = ethernet.ARP_TYPE
            ether.dst = packet.src
            ether.src = EthAddr('de:ad:be:ef:ca:fe')
            ether.payload = arp_reply
            self.resend_packet(ether.pack(), packet_in.in_port)

        # If IP not in look-up table
        if src_ip not in self.ip_to_port:
            self.ip_to_port[str(src_ip)] = packet_in.in_port
            self.port_to_mac[packet_in.in_port] = packet.src

        # If IP is in look-up table
        if str(dst_ip) in self.ip_to_port.keys() and not packet.type == packet.ARP_TYPE:
            # Put the actual MAC address into the packet so the dst host accepts it
            packet.dst = self.port_to_mac[self.ip_to_port[str(dst_ip)]]
            self.resend_packet(packet.pack(), self.ip_to_port[str(dst_ip)])


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part4Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
