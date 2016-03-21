from pox.core import core
from pox.openflow import *
import string
import time
import threading
import pdb
from utils import *
from SimpleL2Learning import SimpleL2LearningSwitch
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.vlan import vlan
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.tcp import tcp
from pox.lib.addresses import IPAddr, EthAddr
import urllib2

log = core.getLogger() # Use central logging service

SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))

FLOW_HARD_TIMEOUT = 30
FLOW_IDLE_TIMEOUT = 10


class LoadBalancerSwitch(SimpleL2LearningSwitch):
	
        def __init__(self, connection, config):
	        SimpleL2LearningSwitch.__init__(self, connection, False)
        	self._connection = connection;
		
		self._serverip1 = config['server_ip1']
		self._serverip2 = config['server_ip2']   
		self._serverip1_mac = config['server_ip1_mac']
		self._serverip2_mac = config['server_ip2_mac']
		
		self._clientip1 = config['client_ip1']
		self._clientip2 = config['client_ip2'] 
		self._clientip3 = config['client_ip3']
		self._clientip4 = config['client_ip4']
		self._clientip1_mac = config['client_ip1_mac']
		self._clientip2_mac = config['client_ip2_mac']
		self._clientip3_mac = config['client_ip3_mac']
		self._clientip4_mac = config['client_ip4_mac']
		

		self.FLAG = 0
		
		self.lock1 = threading.Lock() 
	
		self.thread_flag = 1
		
		
		#Client Threat Status - 0: Low, 1: Medium, 2: High
		self.client1_status = 0;
		self.client2_status = 0;
		self.client3_status = 0;
		
		#Server Threat Status - 0: Low, 1: Medium, 2: High
		self.server1_status = 0;

	def _handle_PacketIn(self, event):
	        #log.debug("Got a packet : " + str(event.parsed))
	        self.packet = event.parsed
	        self.event = event
	        self.macLearningHandle()
		
	        if self.thread_flag == 1:
		    thr1 = threading.Thread(target = self.parseAttackGraph)
		    thr1.start()
		    self.thread_flag = 0
	        
		if packetDstIp(self.packet, self._serverip1, log):
		    if (self.server1_status == 0): #Server 1 is in Normal Mode
		        SimpleL2LearningSwitch._handle_PacketIn(self, event)
				
		    elif (self.server1_status == 1): #Server 1 is in Medium Attack Threat Mode
			if(self.packet.src == self._clientip1_mac):
			    if (self.client1_status == 0):
			        SimpleL2LearningSwitch._handle_PacketIn(self, event)

			    elif (self.client1_status == 1 or self.client1_status == 2): 
				#Block Traffic
				msg = of.ofp_flow_mod()
				msg.priority = 20
				msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
				# create generic match
				match = of.ofp_match()
			        # policy in one direction
				match.dl_src = self._clientip1_mac
				match.nw_dst = self._serverip1
				msg.match = match
	    			event.connection.send(msg)
			
			elif(self.packet.src == self._clientip2_mac):
			    if (self.client2_status == 0):
			        SimpleL2LearningSwitch._handle_PacketIn(self, event)
			    elif (self.client2_status == 1 or self.client2_status == 2): 
				#Block Traffic
			        msg = of.ofp_flow_mod()
		                msg.priority = 20
			        msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
			        # create generic match
			        match = of.ofp_match()
			        # policy in one direction
			        match.dl_src = self._clientip2_mac
			        match.nw_dst = self._serverip1
			        msg.match = match
			        event.connection.send(msg)
							
					
			elif(self.packet.src == self._clientip3_mac):
			    if (self.client3_status == 0):
			        SimpleL2LearningSwitch._handle_PacketIn(self, event)
			    elif (self.client3_status == 1 or self.client3_status == 2): 
				#Block Traffic
				msg = of.ofp_flow_mod()
			    	msg.priority = 20
			    	msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
			    	# create generic match
			    	match = of.ofp_match()
			    	# policy in one direction
			    	match.dl_src = self._clientip3_mac
			    	match.nw_dst = self._serverip1
			    	msg.match = match
			    	event.connection.send(msg)
					
		        elif(self.packet.src == self._clientip4_mac):
		            SimpleL2LearningSwitch._handle_PacketIn(self, event) #Consider Load Balancing Here
						
		    elif (self.server1_status == 2): #Server 1 is in High Attack Threat Mode 
		        if(self.packet.src == self._clientip1_mac or self.packet.src == self._clientip2_mac or self.packet.src == self._clientip3_mac):
			    #Block Traffic
			    msg = of.ofp_flow_mod()
	    		    msg.priority = 20
	    		    msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))	
			    # create generic match
                            match = of.ofp_match()
			    # policy in one direction
			    if(self.packet.src == self._clientip1_mac):
			        match.dl_src = self._clientip1_mac
			    if(self.packet.src == self._clientip2_mac):
			        match.dl_src = self._clientip2_mac
			    if(self.packet.src == self._clientip3_mac):
				match.dl_src = self._clientip3_mac
			    match.nw_dst = self._serverip1
			    msg.match = match
			    event.connection.send(msg)
						
			elif(self.packet.src == self._clientip4_mac):
		            if packetIsTCP(self.packet, log):
			        #Redirect Traffic to Server 2; Modify Dst IP and Dst MAC 
				newaction = createOFAction(of.OFPAT_SET_DL_DST, self._serverip2_mac, log)
				actions.append(newaction)
				newaction = createOFAction(of.OFPAT_SET_NW_DST, self._serverip2, log)
				#log.debug("MAC %s IP %s"%(self._serverip1_mac,self._serverip1))
				actions.append(newaction)
				out_port = 7 ##Check the correct port here
				newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
				actions.append(newaction)
				match = of.ofp_match()
				match.nw_src = self._clientip4
				match.dl_src = self._clientip4_mac
				#match = getFullMatch(self.packet, inport)
				msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
				event.connection.send(msg.pack())
			
		elif (packetDstIp (self.packet, self._clientip4, log) and (self.packet.src == self._serverip2_mac)):
		    if packetIsTCP(self.packet, log):
		        # Modify Source IP and Source Mac
			newaction = createOFAction(of.OFPAT_SET_DL_SRC, self._serverip1_mac, log)
			actions.append(newaction)
			newaction = createOFAction(of.OFPAT_SET_NW_DST, self._serverip1, log)
			#log.debug("MAC %s IP %s"%(self._serverip1_mac,self._serverip1))
			actions.append(newaction)
			out_port = 4 ##Check the correct port here
			newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
			actions.append(newaction)
			match = of.ofp_match()
			match.nw_src = self._serverip2
			match.dl_src = self._serverip2_mac
			#match = getFullMatch(self.packet, inport)
	        	msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        	event.connection.send(msg.pack())
		else: 
		    SimpleL2LearningSwitch._handle_PacketIn(self, event)
			
	
	def parseAttackGraph(self):
	    index = 0
	    while 1:
	        tot_syn_attack        = 0
		tot_icmp_attack       = 0
	    	tot_nmap_scan         = 0
	    	tot_server_attack     = 0 
	    	
	    	fh = open("/var/log/snort/attackGraph", "rw+")
	    	for line in iter(fh):
        	    cur_attack = line.split(':');
		    if (cur_attack[1] == 0):
		        tot_syn_attack = tot_syn_attack + 1;
		    	tot_server_attack = tot_server_attack + 1;
		    elif (cur_attack[1] == 1):
		    	tot_icmp_attack = tot_icmp_attack + 1;
    			tot_server_attack = tot_server_attack + 1;
	    	    elif (cur_attack[1] == 2):
	    		tot_nmap_scan = tot_nmap_scan + 1;
			tot_server_attack = tot_server_attack + 1;
			
		fh.close()
			
		self.lock1.acquire()
		if (tot_syn_attack < 5):
		    self.client1_status = 0;
		elif (tot_syn_attack > 5 and tot_syn_attack <= 10) : 
		    self.client1_status = 1;
		else:
		    self.client1_status = 2;
				
		if (tot_icmp_attack < 5):
		    self.client2_status = 0;
		elif (tot_icmp_attack > 5 and tot_icmp_attack <= 10) : 
		    self.client2_status = 1;
		else:
		    self.client2_status = 2;
				
		if (tot_nmap_scan < 5):
		    self.client3_status = 0;
		elif (tot_nmap_scan > 5 and tot_nmap_scan <= 10) : 
		    self.client3_status = 1;
		else:
		    self.client3_status = 2;
			
		if (tot_server_attack < 5):
		    self.server1_status = 0;
		elif (tot_server_attack > 5 and tot_server_attack <= 10) : 
		    self.server1_status = 1;
		else:
		    self.server1_status = 2;
		self.lock1.release()
	
		time.sleep(60)
			
class LoadBalancer(object):
    def __init__(self, config):
        core.openflow.addListeners(self)
	self._config=config 
    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % (event.connection,))
        LoadBalancerSwitch(event.connection, self._config)
	


def launch(config_file=os.path.join(SCRIPT_PATH, "load.config")):
    log.debug("Starting N-IDPS " + config_file);
    config = readConfigFile(config_file, log)
    core.registerNew(LoadBalancer,config["general"])
