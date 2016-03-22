"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        client1 = self.addHost( 'client1' )
        client2 = self.addHost( 'client2' )
        client3 = self.addHost( 'client3' )
        client4 = self.addHost( 'client4' )
        snort = self.addHost('snort')
        server1 = self.addHost( 'server1' )
        server2 = self.addHost( 'server2' )
        Switch = self.addSwitch( 's1' )

        # Add links
	self.addLink(Switch,client1)
	self.addLink(Switch,client2)
	self.addLink(Switch,client3)
	self.addLink(Switch,client4)
        self.addLink(Switch,snort) 
        self.addLink(Switch, server1);
        self.addLink(Switch, server2);
	

topos = { 'mytopo': ( lambda: MyTopo() ) }
