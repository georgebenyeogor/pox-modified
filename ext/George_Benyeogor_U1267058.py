from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.packet as pkt
from pox.lib.util import dpid_to_str

log = core.getLogger()

VIRTUAL_IP = IPAddr("10.0.0.10")  # The "virtual" IP clients will ping
SERVER_IPS = [IPAddr("10.0.0.5"),
              IPAddr("10.0.0.6")]  # Real server IPs
SERVER_MACS = [EthAddr("00:00:00:00:00:05"),
               EthAddr("00:00:00:00:00:06")]  # Corresponding MACs

class myApp (object):
    def __init__(self):
        self.server_index = 0  # Start with the first server
        self.ip_to_port = {}
        self.ip_to_mac = {}
        self.client_to_server = {}
        self.ip_to_port[SERVER_IPS[0]] = 5
        self.ip_to_port[SERVER_IPS[1]] = 6
        core.openflow.addListeners(self)


    def _handle_ConnectionUp(self, event):
        """
        Called when a switch connects to the controller.
        """
        # Low priority rule: ARP -> Controller
        fm = of.ofp_flow_mod()
        fm.priority = 1
        fm.match.dl_type = ethernet.ARP_TYPE
        fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(fm)
        log.info("Switch %s connected", event.connection.dpid)


    def _handle_PacketIn(self, event):
        dpid = event.connection.dpid
        packet = event.parsed
        if not packet.parsed:
            return

        # If it's ARP
        if packet.type == ethernet.ARP_TYPE:
            log.info("Received ARP packet on switch %s", dpid_to_str(dpid))
            self._handle_arp(event, packet)
            return

        # If it's IP (ICMP)
        if packet.type == ethernet.IP_TYPE:
            log.info("Received IP (ICMP) packet on switch %s", dpid_to_str(dpid))
            self._handle_ip(packet)
            return


    def _handle_arp(self, event, eth_packet):
        """
        Handle ARP requests for:
          1) Virtual IP (Load Balancer logic)
          2) Normal IPs (server -> client or client -> server ARPs)
        """
        arp_req = eth_packet.find('arp')
        if not arp_req:
            return

        inport = event.port

        # Always learn the sender's IP->port->MAC
        self.ip_to_port[arp_req.protosrc] = inport
        self.ip_to_mac[arp_req.protosrc] = arp_req.hwsrc

        if arp_req.opcode == arp.REQUEST:
            log.info("ARP REQUEST: who-has %s?  tell %s", arp_req.protodst, arp_req.protosrc)

            # Case 1: Request is for the Virtual IP
            if arp_req.protodst == VIRTUAL_IP:
                self._handle_virtual_ip_arp(event, arp_req)
                return

            # Case 2: Request is for a "normal" IP we know
            if arp_req.protodst in self.ip_to_mac:
                # Reply directly with the known MAC
                dst_mac = self.ip_to_mac[arp_req.protodst]
                self._send_arp_reply(event, arp_req, dst_mac)
            else:
                log.info("Don't know MAC for %s; ignoring request (no flood).", arp_req.protodst)


    def _handle_virtual_ip_arp(self, event, arp_req):
        """
        Load balancer logic for ARP requests to VIRTUAL_IP
        """
        client_ip = arp_req.protosrc
        inport = event.port

        log.info("ARP request for VIRTUAL IP %s from client %s", VIRTUAL_IP, client_ip)

        # Check if we already mapped client -> server
        if client_ip in self.client_to_server:
            server_ip, server_mac = self.client_to_server[client_ip]
            log.info("Client %s already mapped to server %s", client_ip, server_ip)
        else:
            # Round-robin pick
            server_ip = SERVER_IPS[self.server_index]
            server_mac = SERVER_MACS[self.server_index]
            self.client_to_server[client_ip] = (server_ip, server_mac)
            self.server_index = (self.server_index + 1) % len(SERVER_IPS)
            log.info("Assigned client %s to server %s", client_ip, server_ip)

        # Send ARP reply to the client
        arp_reply = arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.hwsrc = server_mac
        arp_reply.hwdst = arp_req.hwsrc
        arp_reply.protosrc = VIRTUAL_IP
        arp_reply.protodst = arp_req.protosrc
        arp_reply.hwtype = arp_req.hwtype
        arp_reply.prototype = arp_req.prototype
        arp_reply.hwlen = arp_req.hwlen
        arp_reply.protolen = arp_req.protolen

        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.src = server_mac
        ether.dst = arp_req.hwsrc
        ether.payload = arp_reply

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port=inport))
        msg.in_port = inport
        event.connection.send(msg)

        log.info("LB ARP reply: %s is-at %s -> sent to %s", VIRTUAL_IP, server_mac, arp_req.protosrc)

        client_mac = arp_req.hwsrc
        self._install_flow_rules(event.connection, server_ip, server_mac,
                                 client_ip, client_mac)


    def _send_arp_reply(self, event, arp_req, dst_mac):
        """
        Send a normal ARP REPLY: "arp_req.protodst is at dst_mac"
        to the requester (arp_req.protosrc).
        """
        inport = event.port

        log.info("Sending normal ARP reply: %s is-at %s to %s",
                 arp_req.protodst, dst_mac, arp_req.protosrc)

        arp_reply = arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.hwsrc = dst_mac
        arp_reply.hwdst = arp_req.hwsrc
        arp_reply.protosrc = arp_req.protodst
        arp_reply.protodst = arp_req.protosrc
        arp_reply.hwtype = arp_req.hwtype
        arp_reply.prototype = arp_req.prototype
        arp_reply.hwlen = arp_req.hwlen
        arp_reply.protolen = arp_req.protolen

        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.src = dst_mac
        ether.dst = arp_req.hwsrc
        ether.payload = arp_reply

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port=inport))
        msg.in_port = inport
        event.connection.send(msg)


    def _handle_ip(self, packet):
        """
        Handle IP packets if they somehow arrive without flows.
        """
        ipv4_pkt = packet.find('ipv4')
        log.info("Received IP packet from %s to %s", ipv4_pkt.srcip, ipv4_pkt.dstip)


    def _install_flow_rules(self, connection, server_ip, server_mac, client_ip, client_mac):
        """
        Install two flow rules:
        1) Client -> Server: Match on client -> Virtual IP, rewrite to server IP, server MAC
        2) Server -> Client: Match on server IP -> client IP, rewrite source IP to Virtual IP
        """
        client_port = self.ip_to_port.get(client_ip)
        server_port = self.ip_to_port.get(server_ip)

        if not client_port or not server_port:
            log.warning("Port unknown for client %s or server %s", client_ip, server_ip)
            return

        # ---- Flow 1: Client -> Server ----
        fm1 = of.ofp_flow_mod()
        fm1.match.in_port = client_port
        fm1.match.dl_type = 0x0800
        fm1.match.nw_dst = VIRTUAL_IP
        fm1.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        fm1.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))  
 

        # Flow 2: server->client
        fm2 = of.ofp_flow_mod()
        fm2.match.dl_type = 0x0800
        fm2.match.nw_src = server_ip
        fm2.match.nw_dst = client_ip
        fm2.match.in_port = server_port
        fm2.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        fm2.actions.append(of.ofp_action_dl_addr.set_dst(client_mac))

        fm1.actions.append(of.ofp_action_output(port=server_port))
        connection.send(fm1)
        log.info("Installed flow (client->server): %s -> %s", client_ip, server_ip)
        
        fm2.actions.append(of.ofp_action_output(port=client_port))
        connection.send(fm2)
        log.info("Installed flow (server->client): %s -> %s", server_ip, client_ip)


def launch():
    core.registerNew(myApp)
