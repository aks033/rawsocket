import socket, sys
from struct import *
from select import select
import threading


# receiver to get all the packets

def receive_packets():
	 
	#create an INET, STREAMing socket
	try:
	    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	except socket.error , msg:
	    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	    sys.exit()
	 
	# receive a packet
	while True:
	    print(len(packets_list))	
	    packet = s.recvfrom(65565)
	     
	    #packet string from tuple
	    packet = packet[0]
	     
	    #take first 20 characters for the ip header
	    ip_header = packet[0:20]
	     
	    #now unpack them :)
	    iph = unpack('!BBHHHBBH4s4s' , ip_header)
	     
	    version_ihl = iph[0]
	    version = version_ihl >> 4
	    ihl = version_ihl & 0xF
	    
	     
	    iph_length = ihl * 4	
	    s_addr = socket.inet_ntoa(iph[8]);
	    d_addr = socket.inet_ntoa(iph[9]);
	    
	    ip_dict = {"ihl" : ihl, "version" : version, "tos" : iph[1], "total_length" : iph[2], "ip_id" : iph[3], "ip_frag_off" : iph[4], "ttl" : iph[5], "protocol" : iph[6], "source" : s_addr,"destination" : d_addr}

	     
	    tcp_header = packet[iph_length:iph_length+20]
	     
	    #now unpack them :)
	    tcph = unpack('!HHLLBBHHH' , tcp_header)
	     

	    doff_reserved = tcph[4]
	    tcph_length = doff_reserved >> 4

	    tcp_dict = {"source_port " : tcph[0], "dest_port" : tcph[1], "sequence": tcph[2], "ack":tcph[3], "length":tcph_length}
	    	 
	    h_size = iph_length + tcph_length * 4
	    data_size = len(packet) - h_size
	     
	    #get data from the packet
	    data = packet[h_size:]
	     
	    #print 'Data : ' + data
	    
	    packet_dict={"ip_header" : ip_dict, "tcp_header" : tcp_dict, "data": data}

		
	    if packet_dict["ip_header"]["source"]== dest_ip:
	    	packets_list.append(packet_dict) 
		
		 	    
    
def process_packets():
	while "true":
		for i in packets_list:
			print(i["tcp_header"]["sequence"])
			sender_seq = i["tcp_header"]["sequence"]
			sender_ack = i["tcp_header"]["ack"]
			user_data = ''
			tcp_header = get_tcpheader(sender_ack , sender_seq + 1, 0, 0, 0, 1)
			ip_header = get_ipheader(source_ip, dest_ip, tcp_header, user_data)
			packets_list.remove(i)	
			processed_list.append(i)
			packet = ip_header + tcp_header + user_data		
			s.sendto(packet, (dest_ip , 0 )) 
			print("sent")
			user_data = get_request('/cs653/index.html')
			tcp_header = get_tcpheader(sender_ack , sender_seq + 1, 0, 0, 1, 1)
			ip_header = get_ipheader(source_ip, dest_ip, tcp_header, user_data)
			packet = ip_header + tcp_header + user_data		
			s.sendto(packet, (dest_ip , 0 ))
			sys.exit(0)	

# ip header fields
def get_ipheader(source_ip,dest_ip, tcp_header ,user_data):
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0  #precedence[0-2],delay[3], throughput[4],reliability[5], Reserved[6-7]
    ip_tot_len = 0  # kernel will fill the correct total length-----check??
    ip_id = 54321  # Id of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0  # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton(source_ip)  # Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton(dest_ip)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl
	
    # calculate total length

    ip_tot_len = len(tcp_header)+len(user_data)

    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,ip_saddr, ip_daddr)

    #recompute checksum
    ip_check = checksum(ip_header)
    ip_header_check = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,ip_saddr, ip_daddr)
    return ip_header_check


# tcp header fields
def get_tcpheader(seq, ack_seq, fin, syn,psh, ack):
    tcp_source = port   # source port
    tcp_dest = 80   # destination port
    tcp_seq = seq
    tcp_ack_seq = ack_seq
    tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    tcp_fin = 0
    tcp_syn = syn
    tcp_rst = 0
    tcp_psh = psh
    tcp_ack = ack
    tcp_urg = 0
    tcp_window = socket.htons (5840)    #   maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

    # pseudo header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)

    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length);
    psh = psh + tcp_header + user_data;

    tcp_check = checksum(psh)

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header_check = pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)

    return tcp_header_check

# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0 
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2): 
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
    
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
     
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s


def get_request(path):
	return "GET "+path+" HTTP/1.0\r\n\r\n"




packets_list =[]
processed_list = []  
source_ip = '10.0.2.15'
dest_ip = socket.gethostbyname('www-edlab.cs.umass.edu')
print("dest ip :" + dest_ip)
port = 1240

# create a receiver thread
threading.Thread(target=receive_packets).start()

# create a processing thread 
#threading.Thread(target=process_packets).start()

#create a raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)	
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
 
# tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
#s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# now start constructing the packet
packet = '';

#get the ip header --- SYN
user_data = ''
tcp_header = get_tcpheader(454, 0, 0, 1, 0, 0)
ip_header = get_ipheader(source_ip, dest_ip, tcp_header, user_data)

packet = ip_header + tcp_header + user_data
s.sendto(packet, (dest_ip , 0 )) 



