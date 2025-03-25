from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.packet as pkt

log = core.getLogger()

VIRTUAL_IP = IPAddr("10.0.0.10")  # The virtual IP clients will ping
SERVER_IPS = [IPAddr("10.0.0.5"), IPAddr("10.0.0.6")]  # Real servers
SERVER_MACS = [EthAddr("00:00:00:00:00:05"), EthAddr("00:00:00:00:00:06")]

class myApp(object):
    def __init__(self):
        self.server_index = 0
        self.mac_to_port = {}  # Track MAC addresses to switch ports
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s connected", event.connection.dpid)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        # Learn the port for this MAC
        self.mac_to_port[packet.src] = event.port

        if packet.type == ethernet.ARP_TYPE:
            self._handle_arp(event, packet)
            return

        if packet.type == ethernet.IP_TYPE:
            self._handle_ip(event, packet)
            return

    def _handle_arp(self, event, packet):
        arp_req = packet.find('arp')
        if not arp_req:
            return

        if arp_req.opcode == arp.REQUEST and arp_req.protodst == VIRTUAL_IP:
            # Select server via round robin
            server_ip = SERVER_IPS[self.server_index]
            server_mac = SERVER_MACS[self.server_index]
            self.server_index = (self.server_index + 1) % len(SERVER_IPS)

            # Build ARP reply
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

            msg = of.ofp_packet_out()
            msg.data = ether.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            event.connection.send(msg)

            # Install bidirectional flow rules
            self._install_flow_rules(event.connection, event.port,
                                     server_ip, server_mac,
                                     arp_req.protosrc, arp_req.hwsrc)

    def _handle_ip(self, event, packet):
        log.debug("Received unmatched IP packet: %s", packet.find('ipv4'))

    def _install_flow_rules(self, connection, client_port, server_ip, server_mac, client_ip, client_mac):
        # Look up ports
        server_port = self.mac_to_port.get(server_mac)
        client_port_confirmed = self.mac_to_port.get(client_mac)

        if server_port is None or client_port_confirmed is None:
            log.warning("Unknown ports for client/server, skipping rule install")
            return

        # Client -> Server rule
        fm1 = of.ofp_flow_mod()
        fm1.match.in_port = client_port
        fm1.match.dl_type = 0x0800  # IP
        fm1.match.nw_proto = pkt.ipv4.ICMP_PROTOCOL  # ICMP only
        fm1.match.nw_dst = VIRTUAL_IP
        fm1.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        fm1.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        fm1.actions.append(of.ofp_action_output(port=server_port))
        fm1.idle_timeout = 30
        fm1.hard_timeout = 60
        connection.send(fm1)

        # Server -> Client rule
        fm2 = of.ofp_flow_mod()
        fm2.match.in_port = server_port
        fm2.match.dl_type = 0x0800  # IP
        fm2.match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
        fm2.match.nw_src = server_ip
        fm2.match.nw_dst = client_ip
        fm2.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        fm2.actions.append(of.ofp_action_output(port=client_port_confirmed))
        fm2.idle_timeout = 30
        fm2.hard_timeout = 60
        connection.send(fm2)

        log.info("Installed flow from client %s <-> server %s", client_ip, server_ip)

def launch():
    core.registerNew(myApp)
