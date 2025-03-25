from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str


log = core.getLogger()


VIRTUAL_IP = IPAddr("10.0.0.10")  # The "virtual" IP clients will ping
SERVER_IPS = [IPAddr("10.0.0.5"),
              IPAddr("10.0.0.6")] # Real server IPs
SERVER_MACS = [EthAddr("00:00:00:00:00:05"),
               EthAddr("00:00:00:00:00:06")]  # Corresponding MACs

class myApp (object):

    def __init__(self):
      self.server_index = 0 # Start with the first server
      self.ip_to_port = {}
      self.ip_to_port[SERVER_IPS[0]] = 5  
      self.ip_to_port[SERVER_IPS[1]] = 6  
      self.client_to_server = {}
      self.ip_to_mac = {}
      core.openflow.addListeners(self)


    def _handle_ConnectionUp(self, event):
        """
        Called when a switch connects to the controller.
        """
        fm = of.ofp_flow_mod()
        fm.priority = 1 # lower than the default
        fm.match.dl_type = ethernet.ARP_TYPE
        fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(fm)
        log.info("Switch %s connected", event.connection.dpid)


    def _handle_PacketIn(self, event):
        dpid = event.connection.dpid
        packet = event.parsed
        if not packet.parsed:
            log.warning("%s: ignoring unparsed packet", dpid_to_str(dpid))
            return

        a = packet.find('arp')
        if not a: return

        log.info("%s ARP %s %s => %s", dpid_to_str(dpid),
        {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
        'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))

        if not packet.parsed:
            return
        
        # Check if ARP
        if packet.type == ethernet.ARP_TYPE:
            log.info("Received ARP packet")
            self._handle_arp(event, packet)
            return


    def _handle_arp(self, event, packet):
        """
        Handle ARP requests for the virtual IP and reply with
        the chosen server's MAC address. Then install flow rules.
        """
        dpid = event.connection.dpid
        arp_req = packet.find('arp')
        if not arp_req:
            return
        
        if arp_req and arp_req.protosrc not in self.ip_to_port:
            self.ip_to_port[arp_req.protosrc] = event.port

        if arp_req and arp_req.protosrc not in self.ip_to_mac:
            self.ip_to_mac[arp_req.protosrc] = arp_req.hwsrc
        
        if arp_req.opcode == arp.REQUEST:
            log.info("ARP Request who-has %s tell %s", arp_req.protodst, arp_req.protosrc)

        # Check if ARP is a request for the VIRTUAL_IP
        if arp_req.opcode == arp.REQUEST and arp_req.protodst == VIRTUAL_IP:
            log.info("ARP request for virtual IP %s", VIRTUAL_IP)
            # Select a server in round-robin fashion
            client_ip = arp_req.protosrc
            if client_ip in self.client_to_server:
                server_ip, server_mac = self.client_to_server[client_ip]
                log.info("Client %s already mapped to server %s", client_ip, server_ip)
            else:
                server_ip = SERVER_IPS[self.server_index]
                server_mac = SERVER_MACS[self.server_index]
                self.client_to_server[client_ip] = (server_ip, server_mac)
                self.server_index = (self.server_index + 1) % len(SERVER_IPS)
                log.info("Assigned client %s to server %s", client_ip, server_ip)
            self._install_flow_rules(event.connection, server_ip, server_mac, client_ip, arp_req.hwsrc)
            self._send_arp_reply(event, packet, arp_req, server_mac, dpid)

        elif arp_req.opcode == arp.REQUEST:
            if arp_req.protodst in self.ip_to_mac:
            # We know the MAC for this IP -- send ARP reply
                dst_mac = self.ip_to_mac[arp_req.protodst]
                self._send_arp_reply(event, packet, arp_req, dst_mac, dpid)
        

    def _send_arp_reply(self, event, packet, arp_req, mac, dpid):
        """
        Send an ARP reply to the client with the given MAC address.
        """
        arp_reply = arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.hwsrc = mac
        arp_reply.hwdst = arp_req.hwsrc
        arp_reply.protosrc = arp_req.protodst
        arp_reply.protodst = arp_req.protosrc
        arp_reply.hwtype = arp_req.hwtype
        arp_reply.prototype = arp_req.prototype
        arp_reply.hwlen = arp_req.hwlen
        arp_reply.protolen = arp_req.protolen

        ether = ethernet(type=packet.type, src=event.connection.eth_addr,
                        dst=arp_req.hwsrc)
        ether.payload = arp_reply

        log.info("%s answering ARP for %s" % (dpid_to_str(dpid),
                    str(arp_reply.protosrc)))

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.in_port = event.port
        event.connection.send(msg)

        log.info("ARP reply sent: %s is-at %s", arp_req.protodst, mac)


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
