#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.cli import CLI


class part1_topo(Topo):
    def build(self):
        switch1 = self.addSwitch('s1')
        for i in range(1, 5):
            host = self.addHost('h%d' % i)
            self.addLink('h%d' % i,switch1)


topos = {"part1": part1_topo}

if __name__ == "__main__":
    t = part1_topo()
    net = Mininet(topo=t, controller=None)
    net.start()
    CLI(net)
    net.stop()
