# Part 2 of UWCSE's Project 3
#
# based on Lab 4 from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

log = core.getLogger()


class Firewall(object):
    """
    A Firewall object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # disallow ip_v4 traffic
        # ipv4_flow = of.ofp_flow_mod()
        # ipv4_flow.match = of.ofp_match(dl_type=0x8000)
    
        action_flood = of.ofp_action_output(port=of.OFPP_FLOOD)

        # allow icmp
        icmp_new_fm = of.ofp_flow_mod()
        icmp_new_fm.match = of.ofp_match(dl_type=0x0800)
        icmp_new_fm.actions.append(action_flood)
        # only allow icmp
        icmp_new_fm.match.nw_proto = 1

        # allow arp
        arp_new_fm = of.ofp_flow_mod()
        arp_new_fm.match = of.ofp_match(dl_type=0x0806)
        arp_new_fm.actions.append(action_flood)

        # disallow ipv4
        ipv4_flow = of.ofp_flow_mod()
        ipv4_flow.actions.append(of.ofp_action_output(port=of.OFPP_NONE))

        self.connection.send(icmp_new_fm)
        self.connection.send(arp_new_fm)
        self.connection.send(ipv4_flow)


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
        print("Unhandled packet :" + str(packet.dump()))


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Firewall(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
