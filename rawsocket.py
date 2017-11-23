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
	    print(packets_list)
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
		
	    print tcph[0],tcph[1],tcph[2],tcph[3],tcph[4],tcph[5],tcph[6],tcph[7],tcph[8]
	    tcp_dict = {"source_port " : tcph[0], "dest_port" : tcph[1], "sequence": tcph[2], "ack":tcph[3], "length":tcph_length, "flags":tcph[5]}
	    	 
	    h_size = iph_length + tcph_length * 4
	    data_size = len(packet) - h_size
	     
	    #get data from the packet
	    data = packet[h_size:]
	     
	    print 'Data : ' + str(len(data))
	    
	    packet_dict={"ip_header" : ip_dict, "tcp_header" : tcp_dict, "data": data}

		
	    if packet_dict["ip_header"]["source"]== dest_ip:
	    	packets_list.append(packet_dict)


def process_packets():
	while "true":
		for i in packets_list:	
			#if ack then call ack send function
			if(i["tcp_header"]["flags"] == 18):
				send_ack_get(i)
				packets_list.remove(i)	
				processed_list.append(i)
			# if fin or psh/fin(handle)
			elif(i["tcp_header"]["flags"] == 17 or i["tcp_header"]["flags"] == 25):
				if(len(i["data"]) > 0):
					write_to_file(i["data"])
				send_fin(i)
				packets_list.remove(i)	
				processed_list.append(i)
			#if ack then delete drop packet from your sent list
			# if psh/ack then store data and send ack 
			elif(i["tcp_header"]["flags"] == 24 or i["tcp_header"]["flags"] == 16):

				if(len(i["data"]) > 0):
					write_to_file(i["data"])
					print("hellllllllllllllllllllllllllllllllo")
					send_ack(i)
				packets_list.remove(i)	
				processed_list.append(i)


def check_ack_status(ack):
	for packet in processed_list:
		if (ack == packet["tcp_header"]["ack"]):
			return 1
	return 0
def write_to_file(data):
	f = open('index.txt','a+')
	f.write(data)
	f.close	

def send_ack(packet):
	global user_data

	user_data = ""
	# update the sequence no. and ack no.
	sender_seq = packet["tcp_header"]["sequence"]
	sender_ack = packet["tcp_header"]["ack"]
	update_tcp_flags(0,0,0,0,1,0)
	update_seq_ack(sender_ack, sender_seq + len(packet["data"]))

	# recompute headers
	tcp_header = get_tcpheader()
	ip_header = get_ipheader()

	# compute packet
	packet = ip_header + tcp_header + user_data 
	
	#send ack	
	s.sendto(packet, (dest_ip , 0 ))					
			
def send_fin(packet):
	global user_data
	user_data = ""
	# update the sequence no. and ack no.
	sender_seq = packet["tcp_header"]["sequence"]
	sender_ack = packet["tcp_header"]["ack"]
	update_tcp_flags(1,0,0,0,1,0)
	update_seq_ack(sender_ack, sender_seq + len(packet["data"]) + 1)

	# recompute headers
	tcp_header = get_tcpheader()
	ip_header = get_ipheader()

	# compute packet
	packet = ip_header + tcp_header + user_data 
	
	#send ack	
	s.sendto(packet, (dest_ip , 0 ))

def send_ack_get(packet):
	global user_data
	# update the sequence no. and ack no.
	sender_seq = packet["tcp_header"]["sequence"]
	sender_ack = packet["tcp_header"]["ack"]
	update_tcp_flags(0,0,0,0,1,0)
	update_seq_ack(sender_ack, sender_seq + 1)

	# recompute headers
	tcp_header = get_tcpheader()
	ip_header = get_ipheader()

	# compute packet
	packet = ip_header + tcp_header + user_data 
	
	#send ack	
	s.sendto(packet, (dest_ip , 0 ))
	
	#set get request and send the http packet
	user_data = get_request('/cs653/a3.html')
	update_tcp_flags(0,0,0,1,1,0)
	tcp_header = get_tcpheader()
	ip_header = get_ipheader()
	packet = ip_header + tcp_header + user_data		
	s.sendto(packet, (dest_ip , 0 ))
	print("sent")

def update_tcp_flags(fin,syn,rst,psh,ack,urg):  
    global tcp_fin
    tcp_fin = fin
    global tcp_syn
    tcp_syn = syn
    global tcp_rst
    tcp_rst = rst	 
    global tcp_psh
    tcp_psh = psh
    global tcp_ack
    tcp_ack = ack 	
    global tcp_urg
    tcp_urg = urg		

def update_seq_ack(seq,ack):
    global tcp_seq
    tcp_seq = seq
    global tcp_ack_seq
    tcp_ack_seq = ack

def get_data_len(curr_data_acked):
	global data_acked
	return curr_data_acked - data_acked

def get_ipheader():
   
    global ip_check
    ip_check=0	
    #increment the packet id 	
    global ip_id 
    ip_id+=1 
    print ip_id
     			
    #clculate version+ ihl byte	
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
	
    # calculate total length
    ip_tot_len = sys.getsizeof(tcp_header+user_data)
    #print (tcp_header), 
    print ip_tot_len
    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,ip_saddr, ip_daddr)
	
    #recompute checksum
    ip_check = compute_header_checksum(ip_header)
    print ip_check	
    ip_header_check = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,ip_saddr, ip_daddr)
    return ip_header_check



def get_tcpheader():
    global tcp_check
    tcp_check = 0
    global tcp_flags
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
    print tcp_fin, tcp_syn,tcp_rst, tcp_psh,tcp_ack,tcp_urg	
    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
    print(tcp_header)	
    # pseudo header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)

    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length);
    psh = psh + tcp_header + user_data;
    print(psh)
    tcp_check = checksum(psh)
    print("tcp checksum is " +str(tcp_check)) 	
    #print("tcp flags are "+ str(tcp_flags))
    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header_check = pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)

    return tcp_header_check


def compute_header_checksum(header):
		#checksum = 0
		#header = self.get_initialization_header()
		header = unpack('!20B', header)
		ck_sum = 0
		ptr = 0
		size = len(header)
		while size > 1:
			ck_sum += int((str("%02x" % (header[ptr],)) + 
				str("%02x" % (header[ptr+1],))), 16)
			size -= 2
			ptr += 2
		if size:
			ck_sum += header[ptr]
		ck_sum = (ck_sum >> 16) + (ck_sum & 0xffff)
		ck_sum += (ck_sum >>16)
		global ip_check
		ip_check = (~ck_sum) & 0xFFFF
		return ip_check	

# checksum functions needed for calculation checksum
def checksum(message):
    s = 0 
    for i in range(0, len(message), 2):
	w = ord(message[i])
	if (i+1 < len(message)):
		w += (ord(message[i+1]) << 8)
	else:
		w += (0 << 8)
	s = s + w
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
    s = ~s & 0xffff
    return s


def get_request(path):
	return "GET "+path+" HTTP/1.0\r\n\r\n"


#######################################################################################################################
#######################################################################################################################
packets_list =[]
processed_list = []  
source_ip = '10.0.2.15'
dest_ip = socket.gethostbyname('www-edlab.cs.umass.edu')
print("dest ip :" + dest_ip)
data_acked = 0

f =open("index.txt","w+")


#ip header fields 
ip_ihl = 5
ip_ver = 4
ip_tos = 0  #precedence[0-2],delay[3], throughput[4],reliability[5], Reserved[6-7]
ip_tot_len = 0  # kernel will fill the correct total length-----check??
ip_id = 196  # Id of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_TCP
ip_check = 0  # kernel will fill the correct checksum
ip_saddr = socket.inet_aton(source_ip)  # Spoof the source ip address if you want to
ip_daddr = socket.inet_aton(dest_ip)

#tcp header fields 

tcp_source = 5009   # source port
tcp_dest = 80   # destination port
tcp_seq = 1234
tcp_ack_seq = 0
tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
#tcp flags
tcp_fin = 0
tcp_syn = 1
tcp_rst = 0
tcp_psh = 0
tcp_ack = 0
tcp_urg = 0
tcp_window = socket.htons (5840)    # maximum allowed window size
tcp_check = 0
tcp_urg_ptr = 0
tcp_offset_res = (tcp_doff << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

# create a receiver thread
threading.Thread(target=receive_packets).start()

# create a processing thread 
threading.Thread(target=process_packets).start()

#create a raw socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)	
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

user_data = ''
tcp_header = get_tcpheader()
ip_header = get_ipheader()

packet = ip_header + tcp_header + user_data
s.sendto(packet, (dest_ip , 0 )) 
##############################################################################################################################
##############################################################################################################################
