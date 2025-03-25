from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.packet as pkt

log = core.getLogger()


VIRTUAL_IP = IPAddr("10.0.0.10")        # The "virtual" IP clients will ping
SERVER_IPS = [IPAddr("10.0.0.5"),
              IPAddr("10.0.0.6")]      # Real server IPs
SERVER_MACS = [EthAddr("00:00:00:00:00:05"),
               EthAddr("00:00:00:00:00:06")]  # Corresponding MACs

class myApp (object):
    """
    Implements a simple round-robin load balancer with ARP interception.
    """
  
    def __init__(self):
      self.server_index = 0 # Start with the first server
      core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        """
        This is called when a switch connects to the controller.
        """
        log.info("Switch %s connected", event.connection.dpid)

    def _handle_PacketIn(self, event):
        log.info("Received packet from %s", event.connection.dpid)
        log.info("Packet in port %s", event.port)
        log.info("Packet data %s", event.parsed)
        packet = event.parsed
        if not packet.parsed:
            return

        # Check if ARP
        if packet.type == ethernet.ARP_TYPE:
            log.info("Received ARP packet")
            self._handle_arp(event, packet)
            return

        # Check if IP (e.g., ICMP)
        if packet.type == ethernet.IP_TYPE:
            log.info("Received ICMP packet")
            self._handle_ip(event, packet)
            return

    def _handle_arp(self, event, packet):
        """
        Handle ARP requests for the virtual IP and respond with
        the chosen server's MAC address. Also install flow rules.
        """
        arp_req = packet.find('arp')
        if not arp_req:
            return

        # Check if ARP is a request for the VIRTUAL_IP
        if arp_req.opcode == arp.REQUEST and arp_req.protodst == VIRTUAL_IP:
            # 1. Select a server in round-robin fashion
            server_ip = SERVER_IPS[self.server_index]
            server_mac = SERVER_MACS[self.server_index]

            # 2. Bump the index for the next request
            self.server_index = (self.server_index + 1) % len(SERVER_IPS)

            # 3. Craft an ARP reply
            arp_reply = arp()
            arp_reply.opcode = arp.REPLY
            arp_reply.hwsrc = server_mac       
            arp_reply.hwdst = arp_req.hwsrc
            arp_reply.protosrc = VIRTUAL_IP
            arp_reply.protodst = arp_req.protosrc

            ether = ethernet()
            ether.type = ethernet.ARP_TYPE
            ether.src = server_mac
            ether.dst = packet.src
            ether.set_payload(arp_reply)

            # 4. Send ARP reply out the same port the request came in
            msg = of.ofp_packet_out()
            msg.data = ether.pack()
            msg.actions.append(of.ofp_action_output(port = event.port))
            event.connection.send(msg)

            self._install_flow_rules(event.connection, event.port, server_ip, server_mac, arp_req.protosrc, arp_req.hwsrc)

    def _handle_ip(self, event, packet):
        """
        Handle IP packets if they somehow arrive here without flows.
        Typically, if you set up flows properly on ARP, this might not be used as much.
        """
        log.debug("Received IP packet %s", packet.find('ipv4'))

    def _install_flow_rules(self, connection, inport, server_ip, server_mac, client_ip, client_mac):
        """
        Install two flow rules:
        1) Client -> Server:  Match on client -> Virtual IP, rewrite to server IP, server MAC
        2) Server -> Client:  Match on server IP -> client IP, rewrite source IP to Virtual IP
        """
        # Flow 1: Client to Server
        fm1 = of.ofp_flow_mod()
        fm1.match.in_port = inport
        fm1.match.dl_type = 0x0800          # IP type
        fm1.match.nw_dst = VIRTUAL_IP       # Dest is the virtual IP
        fm1.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        fm1.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        connection.send(fm1)

        # Flow 2: Server to Client
        fm2 = of.ofp_flow_mod()

        fm2.match.dl_type = 0x0800
        fm2.match.nw_src = server_ip
        fm2.match.nw_dst = client_ip
        fm2.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        connection.send(fm2)

def launch():

    core.registerNew(myApp)
