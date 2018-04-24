

Part B1 :

   We need to configure R1,R2,R3 and R4 as rip routers by configuring the rip deamon.
   
   Following steps were followed :

   1.) Open /etc/quagga/daemons 
       Enable zebra and ripd by setting their value to yes

   2.) Copy the sample configuration files.
       cp /usr/share/doc/quagga/examples/zebra.conf.sample /etc/quagga/zebra.conf
       cp /usr/share/doc/quagga/examples/ripd.conf.sample /etc/quagga/ripd.conf

   3.) Copy these configuration files to all nodes.
       cp /etc/quagga/* quagga-ixp/configs/H1
       cp /etc/quagga/* quagga-ixp/configs/H2  
       cp /etc/quagga/* quagga-ixp/configs/R1 
       cp /etc/quagga/* quagga-ixp/configs/R2
       cp /etc/quagga/* quagga-ixp/configs/R3
       cp /etc/quagga/* quagga-ixp/configs/R4

   4.) Restart quagga with following command
       sudo /etc/init.d/quagga restart

   5.) Varify deamons are running correctly by running :
       ps -ef | grep quagga

Part B2 :
   
   In this part we need to run rip deamon on each router and host.
   This was done by following steps:
   
   1.) cd miniNExT/util
   
   2.) Following steps were followed for each router and host:
       ./mx H1 ## same for H2, R1, R2, R3 and R4
       telnet localhost 2602
       ripd> en
       ripd# configure terminal
       ripd(config)# router rip
       ripd(config-router)#   network ip ## ip of those interfaces which needs to be advertised
       ripd(config-router)# write
       ripd(config-router)# exit

   
   a.) Screenshots of routing tables are attached.
   b.) Traceroutes between H1 and H2 are attached.
   c.) Time taken for ping 8996 millisec.
   d.) Convergenge Time = 0.068 millisec. Screenshot attached.

Part B3 :

    R1-R2 was on the current path.
    They were broken by logging into R1 and using 
    > no network <ip> command

    Time taken to reestablish connection was approximately 20 seconds.
    Screenshots of traceroutes for previous and new path are attached.




     
