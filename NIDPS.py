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

                #self.report = "~/testreportlog";
		
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
		self.client1_status = 0
		self.client2_status = 0
		self.client3_status = 0
		
		#Server Threat Status - 0: Low, 1: Medium, 2: High
		self.server1_status = 0

                #Info Counters
                self.server1_low_threat             = 0
                self.server1_medium_threat          = 0
                self.server1_high_threat            = 0

                self.client1_low_threat             = 0
                self.client1_medium_threat          = 0
                self.client1_medium_threat          = 0

                self.client2_low_threat             = 0
                self.client2_medium_threat          = 0
                self.client2_medium_threat          = 0

                self.client3_low_threat             = 0
                self.client3_medium_threat          = 0
                self.client3_medium_threat          = 0

                self.client1_traffic_blocked        = 0
                self.client2_traffic_blocked        = 0
                self.client3_traffic_blocked        = 0
                self.user_traffic                   = 0
                self.user_traffic_redirected        = 0
                self.user_return_traffic_redirected = 0
                self.other_traffic                  = 0

	def _handle_PacketIn(self, event):
                inport = event.port
	        self.packet = event.parsed
	        self.event = event
	        self.macLearningHandle()

                actions = []
		
	        if self.thread_flag == 1:
		    thr1 = threading.Thread(target = self.parseAttackGraph)
		    thr1.start()
		    self.thread_flag = 0
	        
		if packetDstIp(self.packet, self._serverip1, log):
		    if (self.server1_status == 0): # Server 1 is in Low Attack Threat Mode
                        # Allow all traffic to pass through to Server 1 : Attack Traffic + Legitimate Traffic
                        self.server1_low_threat = self.server1_low_threat + 1
                        SimpleL2LearningSwitch._handle_PacketIn(self, event)
                        if (self.server1_low_threat % 5000 == 0) :
                            log.info("Server1_Low_Threat_Level: %d Client_Threats: %d, %d, %d" %(self.server1_low_threat, self.client1_status, self.client2_status, self.client3_status))
				
		    elif (self.server1_status == 1): #Server 1 is in Medium Attack Threat Mode
                        #log.info("Packet SRC MAC: %s" %(self.packet.src))
                        self.server1_medium_threat = self.server1_medium_threat + 1
                        if (self.server1_medium_threat % 5000 == 0) :
                            log.info("Server1_Medium_Threat_Level: %d Client_Threats : %d, %d, %d" %(self.server1_medium_threat, self.client1_status, self.client2_status, self.client3_status))
			if(str(self.packet.src) == str(self._clientip1_mac)):
			    if (self.client1_status == 0):
                                self.client1_low_threat = self.client1_low_threat + 1
                                if (self.client1_low_threat % 500 == 0) :
                                    log.info("Server1_Medium_Threat_Level + Client1_Low_Threat_Level: %d " % self.client1_low_threat)
			        SimpleL2LearningSwitch._handle_PacketIn(self, event)
			    elif (self.client1_status == 1 or self.client1_status == 2): 
                                if (self.client1_status == 1):
                                    self.client1_medium_threat = self.client1_medium_threat + 1
                                    if (self.client1_medium_threat % 500 == 0) :
                                        log.info("Server1_Medium_Threat_Level + Client1_Medium_Threat_Level: %d " % self.client1_medium_threat)
                                elif (self.client1_status == 2):
                                    self.client1_high_threat = self.client1_high_threat + 1
                                    if (self.client1_high_threat % 500 == 0) :
                                        log.info("Server1 Medium_Threat_Level + Client1_High_Threat_Level: %d " % self.client1_high_threat)
				#Block Traffic
                                self.client1_traffic_blocked = self.client1_traffic_blocked + 1
                                if (self.client1_traffic_blocked % 500 == 0) :
                                    log.info("Server1_Medium_Threat_Level + Client1_Attack_Blocked: %d " % self.client1_traffic_blocked)
				msg = of.ofp_flow_mod()
				msg.priority = 20
				msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
				# create generic match
				#match = of.ofp_match()
			        # policy in one direction
				#match.dl_src = self._clientip1_mac
				#match.nw_dst = self._serverip1
				match = getFullMatch(self.packet, inport)
				msg.match = match
	    			event.connection.send(msg)
			
			elif(str(self.packet.src) == str(self._clientip2_mac)):
			    if (self.client2_status == 0):
                                self.client2_low_threat = self.client2_low_threat + 1
                                if (self.client2_low_threat % 500 == 0) :
                                    log.info("Server1_Medium_Threat_Level + Client2_Low_Threat_Level: %d " % self.client2_low_threat)
			        SimpleL2LearningSwitch._handle_PacketIn(self, event)
			    elif (self.client2_status == 1 or self.client2_status == 2): 
                                if (self.client2_status == 1):
                                    self.client2_medium_threat = self.client2_medium_threat + 1
                                    if (self.client2_medium_threat % 500 == 0) :
                                        log.info("Server1_Medium_Threat_Level + Client2_Medium_Threat_Level: %d " % self.client2_medium_threat)
                                elif (self.client2_status == 2):
                                    self.client2_high_threat = self.client2_high_threat + 1
                                    if (self.client2_high_threat % 500 == 0) :
                                        log.info("Server1_Medium_Threat_Level + Client2_High_Threat_Level: %d " % self.client2_high_threat)
				#Block Traffic
                                self.client2_traffic_blocked = self.client2_traffic_blocked + 1
                                if (self.client2_traffic_blocked % 500 == 0) :
                                    log.info("Server1_Medium_Threat_Level + Client2_Attack_Blocked: %d " % self.client2_traffic_blocked)
			        msg = of.ofp_flow_mod()
		                msg.priority = 20
			        msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
			        # create generic match
			        #match = of.ofp_match()
			        # policy in one direction
			        #match.dl_src = self._clientip2_mac
			        #match.nw_dst = self._serverip1
				match = getFullMatch(self.packet, inport)
			        msg.match = match
			        event.connection.send(msg)
					
			elif(str(self.packet.src) == str(self._clientip3_mac)):
			    if (self.client3_status == 0):
                                self.client3_low_threat = self.client3_low_threat + 1
                                if (self.client3_low_threat % 500 == 0) :
                                    log.info("Server1_Medium_Threat_Level + Client3_Low_Threat_Level: %d " % self.client3_low_threat)
			        SimpleL2LearningSwitch._handle_PacketIn(self, event)
			    elif (self.client3_status == 1 or self.client3_status == 2): 
                                if (self.client3_status == 1):
                                    self.client3_medium_threat = self.client3_medium_threat + 1
                                    if (self.client3_medium_threat % 500 == 0) :
                                        log.info("Server1_Medium_Threat_Level + Client3_Medium_Threat_Level: %d " % self.client3_medium_threat)
                                elif (self.client3_status == 2):
                                    self.client3_high_threat = self.client3_high_threat + 1
                                    if (self.client3_high_threat % 500 == 0) :
                                        log.info("Server1_Medium_Threat_Level + Client3_High_Threat_Level: %d " % self.client3_high_threat)
				#Block Traffic
                                self.client3_traffic_blocked = self.client3_traffic_blocked + 1
                                if (self.client3_traffic_blocked % 500 == 0) :
                                    log.info("Server1_Medium_Threat_Level + Client3_Attack_Blocked: %d " % self.client3_traffic_blocked)
				msg = of.ofp_flow_mod()
			    	msg.priority = 20
			    	msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
			    	# create generic match
			    	#match = of.ofp_match()
			    	# policy in one direction
			    	#match.dl_src = self._clientip3_mac
			    	#match.nw_dst = self._serverip1
				match = getFullMatch(self.packet, inport)
			    	msg.match = match
			    	event.connection.send(msg)
					
		        elif(str(self.packet.src) == str(self._clientip4_mac)):
                            self.user_traffic = self.user_traffic + 1
                            if (self.user_traffic % 500 == 0) :
                                log.info("Server1_Medium_Threat_Level + User_Traffic_From_Client4: %d " % self.user_traffic)
		            SimpleL2LearningSwitch._handle_PacketIn(self, event) #Consider Load Balancing Here
						
		    elif (self.server1_status == 2): #Server 1 is in High Attack Threat Mode 
                        self.server1_high_threat = self.server1_high_threat + 1
                        if (self.server1_high_threat % 5000 == 0) :
                            log.info("Server1_High_Threat_Level: %d Client_Threats : %d, %d, %d" %(self.server1_high_threat, self.client1_status, self.client2_status, self.client3_status))
		        if(str(self.packet.src) == str(self._clientip1_mac) or str(self.packet.src) == str(self._clientip2_mac) or str(self.packet.src) == str(self._clientip3_mac)):
			    #Block Traffic
			    msg = of.ofp_flow_mod()
	    		    msg.priority = 20
	    		    msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))	
			    # create generic match
                            #match = of.ofp_match()
			    # policy in one direction
			    if(self.packet.src == self._clientip1_mac):
                                self.client1_traffic_blocked = self.client1_traffic_blocked + 1
                                if (self.client1_traffic_blocked % 500 == 0) :
                                    log.info("Server1_High_Threat_Level + Client1_Attack_Blocked: %d " % self.client1_traffic_blocked)
			        #match.dl_src = self._clientip1_mac
			    if(self.packet.src == self._clientip2_mac):
                                self.client2_traffic_blocked = self.client2_traffic_blocked + 1
                                if (self.client2_traffic_blocked % 500 == 0) :
                                    log.info("Server1_High_Threat_Level + Client 2_Attack_Blocked: %d " % self.client2_traffic_blocked)
			        #match.dl_src = self._clientip2_mac
			    if(self.packet.src == self._clientip3_mac):
                                self.client3_traffic_blocked = self.client3_traffic_blocked + 1
                                if (self.client3_traffic_blocked % 500 == 0) :
                                    log.info("Server1_High_Threat_Level + Client3_Attack_Blocked: %d " % self.client3_traffic_blocked)
				#match.dl_src = self._clientip3_mac
			    #match.nw_dst = self._serverip1
			    match = getFullMatch(self.packet, inport)
			    msg.match = match
			    event.connection.send(msg)
						
			elif(str(self.packet.src) == str(self._clientip4_mac)):
		            if packetIsTCP(self.packet, log):
			        #Redirect Traffic to Server 2; Modify Dst IP and Dst MAC 
                                self.user_traffic_redirected = self.user_traffic_redirected + 1
                                log.info("Server1_High_Threat + Traffic_from_client4_Redirected_to_Server2: %d " % self.user_traffic_redirected)
				newaction = createOFAction(of.OFPAT_SET_DL_DST, self._serverip2_mac, log)
				actions.append(newaction)
				newaction = createOFAction(of.OFPAT_SET_NW_DST, self._serverip2, log)
				actions.append(newaction)
				newaction = createOFAction(of.OFPAT_SET_TP_DST, 6001, log)
				actions.append(newaction)
				out_port = 7 ## Outport 7 on OpenVSwitch is connected to Server 2
				newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
				actions.append(newaction)
				#match = of.ofp_match()
				#match.dl_src = str(self._clientip4_mac)
				#match.nw_src = str(self._clientip4)
				match = getFullMatch(self.packet, inport)
				msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
				event.connection.send(msg.pack())
			
		elif (packetDstIp (self.packet, self._clientip4, log) and (str(self.packet.src) == str(self._serverip2_mac))):
		    if packetIsTCP(self.packet, log):
		        # Modify Source IP and Source Mac
                        self.user_return_traffic_redirected = self.user_return_traffic_redirected + 1
                        log.info("Server1_High_Threat + Return_Traffic_to_client4_modified: %d " % self.user_return_traffic_redirected)
			newaction = createOFAction(of.OFPAT_SET_DL_SRC, self._serverip1_mac, log)
			actions.append(newaction)
			newaction = createOFAction(of.OFPAT_SET_NW_SRC, self._serverip1, log)
			actions.append(newaction)
			newaction = createOFAction(of.OFPAT_SET_TP_SRC, 5001, log)
			actions.append(newaction)
			out_port = 4 ## Outport 4 on OpenVSwitch is connected to Client 4 
			newaction = createOFAction(of.OFPAT_OUTPUT, out_port, log)
			actions.append(newaction)
			#match = of.ofp_match()
			#match.dl_src = str(self._serverip2_mac)
			#match.nw_src = str(self._serverip2)
			match = getFullMatch(self.packet, inport)
	        	msg = createFlowMod(match, actions, FLOW_HARD_TIMEOUT, FLOW_IDLE_TIMEOUT, event.ofp.buffer_id)
	        	event.connection.send(msg.pack())
		else: 
                    self.other_traffic = self.other_traffic + 1
                    if (self.other_traffic % 1000 == 0) :
                        log.info("Legitmate_User_Traffic + Return_Traffic: %d " % self.other_traffic)
		    SimpleL2LearningSwitch._handle_PacketIn(self, event)
			
	
	def parseAttackGraph(self):
	    index = 0
	    while 1:
                log.info("#### Refreshing Attack Graph ####")
	        tot_syn_attack        = 0
		tot_icmp_attack       = 0
	    	tot_nmap_scan         = 0
	    	tot_server_attack     = 0 
	    	
	    	fh = open("/var/log/snort/attackgraph", "rw+")
	    	for line in iter(fh):
                    #print ("Parsing Attack %s : " % line)
        	    cur_attack = line.split(',')
                    #print ("Attack type found : " + cur_attack[1])
		    if (int(cur_attack[1]) == 0):
                        #log.info ("Here incrementing type syn attack");
		        tot_syn_attack = tot_syn_attack + 1
		    	tot_server_attack = tot_server_attack + 1
		    elif (int(cur_attack[1]) == 1):
		    	tot_icmp_attack = tot_icmp_attack + 1
    			tot_server_attack = tot_server_attack + 1
	    	    elif (int(cur_attack[1]) == 2):
	    		tot_nmap_scan = tot_nmap_scan + 1
			tot_server_attack = tot_server_attack + 1
			
		fh.close()
			
		if (tot_syn_attack < 5) :
		    self.client1_status = 0;
		elif (tot_syn_attack >= 5 and tot_syn_attack <= 10) : 
		    self.client1_status = 1
		else:
		    self.client1_status = 2
				
		if (tot_icmp_attack < 5):
		    self.client2_status = 0
		elif (tot_icmp_attack >= 5 and tot_icmp_attack <= 10) : 
		    self.client2_status = 1
		else:
		    self.client2_status = 2
				
		if (tot_nmap_scan < 5):
		    self.client3_status = 0
		elif (tot_nmap_scan >= 5 and tot_nmap_scan <= 10) : 
		    self.client3_status = 1
		else:
		    self.client3_status = 2
			
		if (tot_server_attack < 5):
		    self.server1_status = 0
		elif (tot_server_attack >= 5 and tot_server_attack <= 10) : 
		    self.server1_status = 1
		else:
		    self.server1_status = 2

                log.info('*******************************************************************************************');
                log.info('**** Syn Attacks    :  %d  , Client1 STATUS : %d' %(tot_syn_attack,self.client1_status))
                log.info('**** ICMP Attacks   :  %d  , Client2 STATUS : %d' %(tot_icmp_attack,self.client1_status))
                log.info('**** NMAP Scans     :  %d  , Client3 STATUS : %d' %(tot_nmap_scan,self.client3_status))
                log.info('**** Server Attacks :  %d  , Server  STATUS : %d' %(tot_server_attack,self.server1_status))
                log.info('*******************************************************************************************');
	
		time.sleep(20)
			
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
