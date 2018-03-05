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
    ## Extending tcp packet to hold payload
    payload = ''
    req_type = ''
    res_type = ''

tcp_packets = []
http_packets = []
Given_Src_Ip = '174.24.26.76'

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
        if len(bin) > 15:
            pkt.fin = int(bin[15])


        pkt.window = struct.unpack(">H", buffer[48:50])[0]
        pkt.check_sum = struct.unpack(">H", buffer[50:52])[0]
        pkt.urgent_pointer = struct.unpack(">H", buffer[52:54])[0]

        tcp_packets.append(pkt)
        request_type = ""
        response_type = ""

        if len(buffer) > 66:
            if len(buffer) > 68:
                request_type = str(struct.unpack(">s", buffer[66])[0]) + str(struct.unpack(">s", buffer[67])[0]) + str(struct.unpack(">s", buffer[68])[0])
            if len(buffer) > 69:
                response_type = str(struct.unpack(">s", buffer[66])[0]) + str(struct.unpack(">s", buffer[67])[0]) + str(struct.unpack(">s", buffer[68])[0]) + str(struct.unpack(">s", buffer[69])[0])

            if request_type == 'GET' or response_type == 'HTTP':
                if request_type == 'GET':
                    pkt.req_type = 'GET'
                if response_type == 'HTTP':
                    pkt.res_type = 'HTTP'

                for ind in range(66, len(buffer)):
                    pkt.payload += str(struct.unpack(">s", buffer[ind])[0])
                
                http_packets.append(pkt)

def reassemble_http_request_response_http_1080():
    queue = []
    request_response = []

    for pkt in http_packets:
        if (pkt.req_type == 'GET'):
            queue.append(pkt)
        elif (pkt.res_type == 'HTTP'):
            request_response.append((queue.pop(0), pkt))

    print "Request/Response assemply for http_1080 : "
    for ind in range(0, len(request_response)):
        pair = request_response[ind]
        print "" ## new line
        print "Request No : " + str(ind + 1)
        print "Request Type : GET request"
        print "Src Address : " + str(pair[0].src_ip) + ":" + str(pair[0].src_port) + ", Dest Address : " + pair[0].dest_ip + ":" + str(pair[0].dest_port) \
                + ", Seq Num : " + str(pair[0].seq_num) + ", Ack Num : " + str(pair[0].ack_num)
        print "Request Type : HTTP response"
        print "Src Address : " + str(pair[1].src_ip) + ":" + str(pair[1].src_port) + ", Dest Address : " + pair[1].dest_ip + ":" + str(pair[1].dest_port) \
                + ", Seq Num : " + str(pair[1].seq_num) + ", Ack Num : " + str(pair[1].ack_num)
        print "" ## new line

    print "" ## new line




def print_connections_with_1080():
    conn = 0
    for pkt in tcp_packets:
        if pkt.ack == 1 and pkt.syn == 1:
            conn += 1

    print "Total connections for port 1080 : " + str(conn)
    if conn > 10:
        print "Since each object is transferred in different TCP connection, HTTP protocol is : HTTP/1.0"


def print_connections_with_1081():
    conn = 0
    for pkt in tcp_packets:
        if pkt.ack == 1 and pkt.syn == 1:
            conn += 1

    print "Total connections for port 1081 : " + str(conn)
    if conn >= 5 and conn <= 8:
        print "Since fixed multiple TCP connections are used to tranfer objects, HTTP protocol is : HTTP/1.1"


def print_connections_with_1082():
    conn = 0
    for pkt in tcp_packets:
        if pkt.ack == 1 and pkt.syn == 1:
            conn += 1

    print "Total connections for port 1082 : " + str(conn)
    if conn == 1:
        print "Since single TCP connections are used to transfer objects, HTTP protocol is : HTTP/2"

def print_pkts_bytes_time():
    bytes = 0
    latest_time_with_data = 0
    initial_time = 0
    for pkt in tcp_packets:
        if initial_time == 0:
            initial_time = pkt.time_stamp

        if pkt.length > 150:
            latest_time_with_data = pkt.time_stamp
        bytes += pkt.length
    
    print "Total pkts send : " + str(len(tcp_packets))
    print "Total bytes transferred : " + str(bytes)
    print "Time taken to load page : " + str(latest_time_with_data - initial_time)


## https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
## http://www.kroosec.com/2012/10/a-look-at-pcap-file-format.html
if __name__ == "__main__":

    print "" ## new line
    
    f = open('http_1080.pcap')
    pcap = dpkt.pcap.Reader(f)
    for timestamp, buffer in pcap:
	parse_and_fill_tcp_packets(timestamp, buffer)
    f.close()

    reassemble_http_request_response_http_1080()
    print_pkts_bytes_time()
    print_connections_with_1080()
    print ""


    tcp_packets = []
    http_packets = []
    f = open('tcp_1081.pcap')
    pcap = dpkt.pcap.Reader(f)
    for timestamp, buffer in pcap:
        parse_and_fill_tcp_packets(timestamp, buffer)
    f.close()

    print_pkts_bytes_time()
    print_connections_with_1081()
    print ""

    tcp_packets = []
    http_packets = []
    f = open('tcp_1082.pcap')
    pcap = dpkt.pcap.Reader(f)
    for timestamp, buffer in pcap:
        parse_and_fill_tcp_packets(timestamp, buffer)
    f.close()

    print_pkts_bytes_time()
    print_connections_with_1082()

    print "" ## New line
    
