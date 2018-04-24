
Routing tables and traceroute are attached in this folder.

Following are the steps to create static routing table.

1.) First of all we need to enable ip-forwarding at each node. This was done as follows :
    a.) Add nodes in topo.py
    b.) Run sudo python start.py
        This will set up the network with given nodes. verify it with command nodes
    c.) Run following command on mininet console :
        
             H1 echo 1 > /proc/sys/net/ipv4/ip_forward
             R1 echo 1 > /proc/sys/net/ipv4/ip_forward
             R2 echo 1 > /proc/sys/net/ipv4/ip_forward
             R3 echo 1 > /proc/sys/net/ipv4/ip_forward
             R4 echo 1 > /proc/sys/net/ipv4/ip_forward
             H2 echo 1 > /proc/sys/net/ipv4/ip_forwar

2.) Next, for the given topology, we need to add network interfaces.
    Other than what is mentioned in topo.py we added following interfaces.

    R1 ip addr add 173.0.0.2/20 dev R1-eth1
    R1 ip addr add 174.0.0.2/20 dev R1-eth2
    R2 ip addr add 175.0.0.2/20 dev R2-eth1
    R3 ip addr add 176.0.0.2/20 dev R3-eth1
    R4 ip addr add 175.0.0.1/20 dev R4-eth1
    R4 ip addr add 176.0.0.1/20 dev R4-eth2

3.) Now, static route of each node is configured as follows:

    H1 ip route add 173.0.0.0/20 via 172.0.0.2 dev H1-eth0
    H1 ip route add 174.0.0.0/20 via 172.0.0.2 dev H1-eth0
    H1 ip route add 175.0.0.0/20 via 172.0.0.2 dev H1-eth0
    H1 ip route add 176.0.0.0/20 via 172.0.0.2 dev H1-eth0
    H1 ip route add 177.0.0.0/20 via 172.0.0.2 dev H1-eth0

    R1 ip route add 175.0.0.0/20 via 173.0.0.1 dev R1-eth1
    R1 ip route add 176.0.0.0/20 via 174.0.0.1 dev R1-eth2
    R1 ip route add 177.0.0.0/20 via 173.0.0.1 dev R1-eth1

    R2 ip route add 172.0.0.0/20 via 173.0.0.2 dev R2-eth0
    R2 ip route add 174.0.0.0/20 via 173.0.0.2 dev R2-eth0
    R2 ip route add 176.0.0.0/20 via 175.0.0.1 dev R2-eth1
    R2 ip route add 177.0.0.0/20 via 175.0.0.1 dev R2-eth1

    R3 ip route add 172.0.0.0/20 via 174.0.0.2 dev R3-eth0
    R3 ip route add 173.0.0.0/20 via 174.0.0.2 dev R3-eth0
    R3 ip route add 175.0.0.0/20 via 176.0.0.1 dev R3-eth1
    R3 ip route add 177.0.0.0/20 via 176.0.0.1 dev R3-eth1

    R4 ip route add 172.0.0.0/20 via 176.0.0.2 dev R4-eth2
    R4 ip route add 173.0.0.0/20 via 175.0.0.2 dev R4-eth1
    R4 ip route add 174.0.0.0/20 via 176.0.0.2 dev R4-eth2

    H2 ip route add 172.0.0.0/20 via 177.0.0.2 dev H2-eth0
    H2 ip route add 173.0.0.0/20 via 177.0.0.2 dev H2-eth0
    H2 ip route add 174.0.0.0/20 via 177.0.0.2 dev H2-eth0
    H2 ip route add 175.0.0.0/20 via 177.0.0.2 dev H2-eth0
    H2 ip route add 176.0.0.0/20 via 177.0.0.2 dev H2-eth0

4.) Finally we need to enable iptable utility to forward and reverse packets through nodes.

    R2 iptables -t nat -A POSTROUTING -o R2-eth1 -j MASQUERADE
    R2 iptables -A FORWARD -i R2-eth0 -o R2-eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
    R2 iptables -A FORWARD -i R2-eth0 -o R2-eth1 -j ACCEPT
	
    R4 iptables -A FORWARD -i R4-eth0 -o R4-eth2 -j ACCEPT
    R4 iptables -A FORWARD -i R4-eth0 -o R4-eth2 -m state --state RELATED,ESTABLISHED -j ACCEPT
    R4 iptables -t nat -A POSTROUTING -o R4-eth2 -j MASQUERADE



Few links which were refered to understand are :
1.) https://linuxconfig.org/how-to-turn-on-off-ip-forwarding-in-linux
2.) https://p5r.uk/blog/2010/ifconfig-ip-comparison.html
3.) https://www.garron.me/en/linux/iptables-manual.html
