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
        leftHost = self.addHost( 'ts1' )
        rightHost = self.addHost( 'ts2' )
        Switch = self.addSwitch( 's1' )
        aggregator = self.addHost( 'aggregator' )
	source = self.addHost('source')
        snort = self.addHost('snort')

        # Add links
	self.addLink(Switch,source)
        self.addLink(Switch,leftHost)
        self.addLink(Switch,rightHost)
        self.addLink(Switch,snort) 
        self.addLink(leftHost,aggregator)
	self.addLink(rightHost,aggregator)
	

topos = { 'mytopo': ( lambda: MyTopo() ) }
