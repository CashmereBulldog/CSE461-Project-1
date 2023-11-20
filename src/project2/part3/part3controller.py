# Part 3 of UWCSE's Mininet-SDN project
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

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


class Part3Controller(object):
    """
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        print(connection.dpid)
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        arp_new_fm = of.ofp_flow_mod()
        arp_new_fm.match = of.ofp_match(dl_type=0x0806)
        arp_new_fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(arp_new_fm)

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
        h10_fm = of.ofp_flow_mod()
        h10_fm.match = of.ofp_match(dl_type=0x0800)
        h10_fm.match.nw_dst = SUBNETS["h10"]
        h10_fm.actions.append(of.ofp_action_output(port=10))
        self.connection.send(h10_fm)

        from_h10_fm = of.ofp_flow_mod()
        from_h10_fm.match = of.ofp_match(dl_type=0x0800)
        from_h10_fm.match.nw_src = SUBNETS["h10"]
        from_h10_fm.actions.append(of.ofp_action_output(port=20))
        self.connection.send(from_h10_fm)

    def s2_setup(self):
        # put switch 2 rules here
        h20_fm = of.ofp_flow_mod()
        h20_fm.match = of.ofp_match(dl_type=0x0800)
        h20_fm.match.nw_src = SUBNETS["h20"]
        h20_fm.actions.append(of.ofp_action_output(port=20))
        self.connection.send(h20_fm)

        from_h20_fm = of.ofp_flow_mod()
        from_h20_fm.match = of.ofp_match(dl_type=0x0800)
        from_h20_fm.match.nw_src = SUBNETS["h20"]
        from_h20_fm.actions.append(of.ofp_action_output(port=10))
        self.connection.send(from_h20_fm)

    def s3_setup(self):
        '''
        # put switch 3 rules here
        h30_fm = of.ofp_flow_mod()
        h30_fm.match.nw_dst = SUBNETS["h30"]
        h30_fm.actions.append(of.ofp_action_output(port=30))
        self.connection.send(h30_fm)

        from_h30_fm = of.ofp_flow_mod()
        from_h30_fm.match.nw_src = SUBNETS["h30"]
        from_h30_fm.actions.append(of.ofp_action_output(port=10))
        self.connection.send(from_h30_fm)
        '''

    def cores21_setup(self):
        # Don't allow icmp traffic from hnotrust
        '''
        icmp_notrust_fm = of.ofp_flow_mod()
        icmp_notrust_fm.match = of.ofp_match(dl_type=0x0800)
        icmp_notrust_fm.match.nw_proto = 1
        icmp_notrust_fm.match.nw_src = SUBNETS["hnotrust"]
        icmp_notrust_fm.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
        self.connection.send(icmp_notrust_fm)

        ip_hnotrust_fm = of.ofp_flow_mod()
        ip_hnotrust_fm.match.nw_dst = SUBNETS["hnotrust"]
        ip_hnotrust_fm.actions.append(of.ofp_action_output(port=1))
        self.connection.send(ip_hnotrust_fm)
        '''

        ip_h10_fm = of.ofp_flow_mod()
        ip_h10_fm.match = of.ofp_match(dl_type=0x0800)
        ip_h10_fm.match.nw_dst = SUBNETS["h10"]
        ip_h10_fm.actions.append(of.ofp_action_output(port=10))
        self.connection.send(ip_h10_fm)

        ip_h20_fm = of.ofp_flow_mod()
        ip_h20_fm.match = of.ofp_match(dl_type=0x0800)
        ip_h20_fm.match.nw_dst = SUBNETS["h20"]
        ip_h20_fm.actions.append(of.ofp_action_output(port=20))
        self.connection.send(ip_h20_fm)

        '''
        ip_h30_fm = of.ofp_flow_mod()
        ip_h30_fm.match.nw_dst = SUBNETS["h30"]
        ip_h30_fm.actions.append(of.ofp_action_output(port=30))
        self.connection.send(ip_h30_fm)

        ip_dc_fm = of.ofp_flow_mod()
        ip_dc_fm.match.nw_dst = SUBNETS["serv1"]
        ip_dc_fm.actions.append(of.ofp_action_output(port=31))
        self.connection.send(ip_dc_fm)
        '''

    def dcs31_setup(self):
        '''
        # put datacenter switch rules here
        icmp_notrust_fm = of.ofp_flow_mod()
        icmp_notrust_fm.match = of.ofp_match(dl_type=0x0800)
        icmp_notrust_fm.match.nw_src = SUBNETS["hnotrust"]
        icmp_notrust_fm.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
        self.connection.send(icmp_notrust_fm)

        h31_fm = of.ofp_flow_mod()
        h31_fm.match.nw_dst = SUBNETS["serv1"]
        h31_fm.actions.append(of.ofp_action_output(port=31))
        self.connection.send(h31_fm)

        from_h31_fm = of.ofp_flow_mod()
        from_h31_fm.match.nw_src = SUBNETS["serv1"]
        from_h31_fm.actions.append(of.ofp_action_output(port=10))
        self.connection.send(from_h31_fm)
        '''

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
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.
        print(
            "Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump()
        )


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
