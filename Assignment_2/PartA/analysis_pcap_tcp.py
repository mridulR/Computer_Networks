'''
dpkt will give string of bytes so struct will be used to pack it into integer and string data types.
While unpacking, struct can be passed with >/< so that endianess is taken care of.
'''
## https://pymotw.com/2/struct/
import struct
import dpkt

## https://www.pacificsimplicity.ca/blog/reading-packet-hex-dumps-manually-no-wireshark
## https://www.techrepublic.com/article/exploring-the-anatomy-of-a-data-packet/

'''
Ethernet header is 14 bytes and in IP header after 12 bytes src and dest ip is given.
So we will parse the packet from 14+12 = 26 th byte. In 24th byte Ip header, verify
if the packet is tcp == 6 or udp == 11.
'''

class TCP_Packet:
    time_stamp = 0
    length = 0
    src_ip = ''
    dest_ip = ''
    src_port = 0
    dest_port = 0
    seq_num = 0
    ack_num = 0
    offset = 0
    reserved = 0
    ## ECN - http://www.networksorcery.com/enp/protocol/tcp.htm
    ns = 0
    cwr = 0
    ece = 0
    ## ECN - covered
    ## Control Bits
    urg = 0
    ack = 0
    psh = 0
    rst = 0
    syn = 0
    fin = 0
    ## Control Bits covered
    window = 0
    check_sum = 0
    urgent_pointer = 0

tcp_packets = []
Given_Src_Ip = '130.245.145.12'

def parse_and_fill_tcp_packets(time_stamp, buffer):
    if struct.unpack(">B", buffer[23])[0] == 6: ## Fill TCP packets
        pkt = TCP_Packet()

        pkt.time_stamp = time_stamp
        pkt.length = len(buffer)

        src_ip_bytes = [str(struct.unpack(">B", buffer[26])[0]), str(struct.unpack(">B", buffer[27])[0]), 
                str(struct.unpack(">B", buffer[28])[0]), str(struct.unpack(">B", buffer[29])[0])]
        pkt.src_ip = '.'.join(src_ip_bytes).decode('utf-8')
        ## print(pkt.src_ip)

        dest_ip_bytes = [str(struct.unpack(">B", buffer[30])[0]), str(struct.unpack(">B", buffer[31])[0]),
                str(struct.unpack(">B", buffer[32])[0]), str(struct.unpack(">B", buffer[33])[0])]
        pkt.dest_ip = '.'.join(dest_ip_bytes).decode('utf-8')

        pkt.src_port = struct.unpack(">H", buffer[34:36])[0]
        pkt.dest_port = struct.unpack(">H", buffer[36:38])[0]
        ## print "source : " + str(pkt.src_port) + "  -  " + str(pkt.dest_port)

        pkt.seq_num = struct.unpack(">I", buffer[38:42])[0]
        pkt.ack_num = struct.unpack(">I", buffer[42:46])[0]
       
        ## Handling binary data - https://www.devdungeon.com/content/working-binary-data-python
        bin = "{0:b}".format(struct.unpack(">H", buffer[46:48])[0])


        pkt.offset = int(bin[0:4], 2)
        pkt.reserved = int(bin[4:7], 2)

        pkt.ns = int(bin[7])
        pkt.cwr = int(bin[8])
        pkt.ece = int(bin[9])

        pkt.urg = int(bin[10])
        pkt.ack = int(bin[11])
        pkt.psh = int(bin[12])
        pkt.rst = int(bin[13])
        pkt.syn = int(bin[14])
        pkt.fin = int(bin[15])


        pkt.window = struct.unpack(">H", buffer[48:50])[0]
        pkt.check_sum = struct.unpack(">H", buffer[50:52])[0]
        pkt.urgent_pointer = struct.unpack(">H", buffer[52:54])[0]

        tcp_packets.append(pkt)

def get_connection_mapping():
    map = {}
    for tcp_packet in tcp_packets:
        key = (tcp_packet.src_ip, tcp_packet.src_port, tcp_packet.dest_ip, tcp_packet.dest_port)
        if key not in map.keys():
            map[key] = []
        
        map[key].append(tcp_packet)
    return map

def print_seq_ack_rcv_wind(pkts_send, pkts_rcvd):
    seq_ack_rcv_win = set()
    for send in range(2, len(pkts_send)): ## After SYN and ACK packets
        for rcv in range(1, len(pkts_rcvd)): ## After SYN/ACK packet

            if pkts_send[send].seq_num + pkts_send[send].length - 66 == pkts_rcvd[rcv].ack_num:
                seq_ack_rcv_win.add((pkts_send[send].seq_num, pkts_send[send].ack_num, \
                    pkts_rcvd[rcv].seq_num, pkts_rcvd[rcv].ack_num, pkts_send[send].window))

            if len(seq_ack_rcv_win) == 2:
                break
    for val in seq_ack_rcv_win:
        print(val)

def print_throughput(pkts_send, pkts_rcvd):
    total_send_data = 0
    for tcp_packet in pkts_send:
        total_send_data += tcp_packet.length

    sorted_pkts_send = sorted(pkts_send, key = lambda x : x.time_stamp, reverse = False)
    sorted_pkts_rcvd = sorted(pkts_rcvd, key = lambda x : x.time_stamp, reverse = True)

    print "Total data send : " + str(total_send_data)
    print "Total time taken : " + str(sorted_pkts_rcvd[0].time_stamp - sorted_pkts_send[0].time_stamp)
    print "Throughput : " + str(total_send_data / (sorted_pkts_rcvd[0].time_stamp - sorted_pkts_send[0].time_stamp))

def print_loss_rate(pkts_send):
    pkts_lost = 0
    seq_nums_seen = []
    for ind in range(3, len(pkts_send)):
        if pkts_send[ind].seq_num in seq_nums_seen:
            pkts_lost += 1
        else :
            seq_nums_seen.append(pkts_send[ind].seq_num)
    
    print "Loss rate : " + str(pkts_lost * 1.0 / len(pkts_send) )
    return pkts_lost

def print_avg_RTT(pkts_send, pkts_rcvd):
    seq_mapping = {}
    ack_mapping = {}

    for send in pkts_send:
        if not (send.seq_num in seq_mapping.keys()):
            seq_mapping[send.seq_num] = send.time_stamp

    for rcv in pkts_rcvd:
        if not (rcv.ack_num in ack_mapping.keys()):
            ack_mapping[rcv.ack_num] = rcv.time_stamp

    total_pkts = 0
    total_time_taken = 0
    count = 0
    for key in seq_mapping.keys():
        if key in ack_mapping.keys():
            total_pkts += 1
            total_time_taken += (ack_mapping[key] - seq_mapping[key])
        else:
            count += 1

    print "Average RTT : " + str((total_time_taken * 1.0) / total_pkts) ## + "----" + str(count)

def print_congestion_window(key):
    filter_pkts = []

    for ind in range(0, len(tcp_packets)):
        pkt = tcp_packets[ind]
        if (pkt.src_ip == key[0] and pkt.src_port == key[1] and pkt.dest_ip == key[2] and pkt.dest_port == key[3]) or \
            (pkt.src_ip == key[2] and pkt.src_port == key[3] and pkt.dest_ip == key[0] and pkt.dest_port == key[1]):
            filter_pkts.append(pkt)

    syn = 0
    win_count = 0
    for pkt in filter_pkts:
        if pkt.src_ip == Given_Src_Ip:
            syn = pkt.seq_num

        if pkt.dest_ip == Given_Src_Ip and syn != 0 and syn - pkt.ack_num > 0:
            win_count = win_count + 1
            print "Congestion window : " + str(syn - pkt.ack_num)
            syn = 0

        if win_count == 10:
            break

def print_no_of_retransmissions(pkts_send, pkts_rcvd, pkts_lost):
    seq_lost_mapping = {}
    ack_lost_mapping = {}

    for send in pkts_send:
        if not (send.seq_num in seq_lost_mapping.keys()):
            seq_lost_mapping[send.seq_num] = 0

        seq_lost_mapping[send.seq_num] += 1

    for rcv in pkts_rcvd:
        if not (rcv.ack_num in ack_lost_mapping.keys()):
            ack_lost_mapping[rcv.ack_num] = 0

        ack_lost_mapping[rcv.ack_num] += 1


    triple_ack_loss = 0
    for key in seq_lost_mapping.keys():
        if key in ack_lost_mapping.keys() and ack_lost_mapping[key] > 2:
            triple_ack_loss += 1

    print "Retransmission due to triple duplicate ack : " + str(triple_ack_loss)
    print "Retransmission due to timeout : " + str(pkts_lost - triple_ack_loss)


def print_num_of_tcp_flow_with_details():
    tcp_flows = 0
    conn_mapping = get_connection_mapping()

    for key in conn_mapping.keys():
        if key[0] == Given_Src_Ip:
            other_end_conn_key = (key[2], key[3], key[0], key[1])
            pkts_send = conn_mapping[key]
            pkts_rcvd = conn_mapping[other_end_conn_key]

            #total_send_pkts = len(pkts_send)

            for tcp_packet in pkts_rcvd:
                if tcp_packet.ack == 1 and tcp_packet.syn == 1:
                    tcp_flows = tcp_flows + 1
            
            ## Part A - 2.a
            if tcp_flows < 3:
                print "For flow : " + str(tcp_flows)
                print "Sender Seq Num, Sender Ack Num, Receiver Seq Num, Receiver Ack Num, Window Size"
                print_seq_ack_rcv_wind(pkts_send, pkts_rcvd)
                print ""
            ## Part A - 2.b
            print_throughput(pkts_send, pkts_rcvd)
            ## Part A - 2.c
            pkts_lost = print_loss_rate(pkts_send)
            ## Part A - 2.d
            print_avg_RTT(pkts_send, pkts_rcvd)
            ## Part B - 1
            print_congestion_window(key)
            ## Part B - 2
            print_no_of_retransmissions(pkts_send, pkts_rcvd, pkts_lost)

            print "" ## New line


    ## Part A - 1
    print "TCP Flows : " + str(tcp_flows)



## https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
## http://www.kroosec.com/2012/10/a-look-at-pcap-file-format.html
if __name__ == "__main__":
    print "Input file - assignment2.pcap"
    print "" ## new line
    f = open('assignment2.pcap')
    pcap = dpkt.pcap.Reader(f)

    for timestamp, buffer in pcap:
	## print timestamp, len(buffer) , " -> ", struct.unpack(">B", buffer[23])[0]
	parse_and_fill_tcp_packets(timestamp, buffer)

	'''
	eth = dpkt.ethernet.Ethernet(buffer)
	ip = eth.data
    	tcp = ip.data

    	if tcp.dport == 80 and len(tcp.data) > 0:
        	http = dpkt.http.Request(tcp.data)
        	print http.uri
	'''
    f.close()

    #print len(tcp_packets)
    #print len(get_connection_mapping())
    print_num_of_tcp_flow_with_details()
    print "" ## New line
    




