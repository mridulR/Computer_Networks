import dpkt


## https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
if __name__ == "__main__":
    print "Input file - assignment2.pcap"
    f = open('assignment2.pcap')
    pcap = dpkt.pcap.Reader(f)

	
    for ts, buf in pcap:
	print ts, buf
