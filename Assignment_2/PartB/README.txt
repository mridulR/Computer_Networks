

This code is  same as the one in part A.
Few print statements have been removed so that there is clarity in output.

How congestion window size was calculated ?

    Explanation : First we iterate through all the packets send from source ip. We keep the latest seq number from these packets. Now
                  whenever any acknowledgement is received, we check check for the difference between latest seq num and ack num. This is the congestion window size
                  as the amouth of bytes that can be on the wire without acknowledgement.

                  Congestion window size initially grows because it follows additive increase multiplicative decrease feedback approach. So initially, there is no packet loss,
                  hence, congestion window size keeps on increasing.

                  Congestion window is estimated at both sender and receiver side because its a bi-directional channel. However, here we are analysing the pcap file. So TCP has already 
                  negotiated congestion window size by taking inputs from both sender and receiver. Whereever we estimate this value wheather at sender or receiver, we will get the same
                  value.



How to compute the number of times a retransmission	occurred due to	triple duplicate ack and the number	of time a retransmission occurred due to timeout ?

    Explanation : For calculating triple duplicate ack, we maintain a mapping of seq and ack counts for packets. Now iterating over the seq mapping of packets, we find the count from ack
                  mapping. For each ack count which is greater than 2 we increase the count of triple duplicate ack. Now, to get retransmission occurred due to timeout we subtract
                  triple duplicate ack from total packet loss calculated earlier.

Following are the captured data :

        Flow 1:
                Initial Congestion window = 1 * MSS = 1460
                
                Congestion window : 11584
                Congestion window : 13032
                Congestion window : 15928
                Congestion window : 17376
                Congestion window : 17376
                Congestion window : 18824
                Congestion window : 26064
                Congestion window : 27512
                Congestion window : 33304
                Congestion window : 33304
        
        Flow 2:
                Initial Congestion window = 1 * MSS = 1460

                Congestion window : 11584
                Congestion window : 13032
                Congestion window : 26064
                Congestion window : 27512
                Congestion window : 24616
                Congestion window : 24616
                Congestion window : 27512
                Congestion window : 27512
                Congestion window : 27512
                Congestion window : 27512

        Flow 3:
                Initial Congestion window = 1 * MSS = 1460

                Congestion window : 11584
                Congestion window : 13032
                Congestion window : 14480
                Congestion window : 15928
                Congestion window : 17376
                Congestion window : 18824
                Congestion window : 20272
                Congestion window : 26064
                Congestion window : 27512
                Congestion window : 33304


