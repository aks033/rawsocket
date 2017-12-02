import os
import random
import socket, sys
from struct import *
from select import select
import threading
from datetime import datetime 
from datetime import timedelta 

# receiver thread to get all the packets
def receive_packets():
	 
	#create an INET, STREAMing socket to listen to incoming packets
	try:
	    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	except socket.error , msg:
	    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	    sys.exit()
	 
	# Continuously recieve packets. Drop them if they are duplicate otherwise add valid packets 
	# to the packet_lists for further processing.  
	while True:
	   
	    packet = s.recvfrom(65565)
	    #packet string from tuple

	    packet = packet[0]
	    #take first 20 characters for the IP header
	    ip_header = packet[0:20]
	    #now unpack them :)
	    iph = unpack('!BBHHHBBH4s4s' , ip_header)	 
	    version_ihl = iph[0]
	    version = version_ihl >> 4
	    ihl = version_ihl & 0xF
	    iph_length = ihl * 4
	    #convert IP adress IPv4 numbers-and-dots notation to binary data	
	    s_addr = socket.inet_ntoa(iph[8]);
	    d_addr = socket.inet_ntoa(iph[9]);
	    
	    #create a dictionary with all IP header parameters
	    ip_dict = {"ihl" : ihl, "version" : version, "tos" : iph[1], "total_length" : iph[2], "ip_id" : iph[3], "ip_frag_off" : iph[4], "ttl" : iph[5], "protocol" : iph[6], "source" : s_addr,"destination" : d_addr}

	    #Next 20 characters for TCP header 
	    tcp_header = packet[iph_length:iph_length+20]
	    
	     
	    #Unpack them 
	    tcph = unpack('!HHLLBBHHH' , tcp_header) 

	    doff_reserved = tcph[4]
	    tcph_length = doff_reserved >> 4
		
	    #create a dictionary of TCP header parameters
	    tcp_dict = {"source_port " : tcph[0], "dest_port" : tcph[1], "sequence": tcph[2], "ack":tcph[3], "length":tcph_length, "flags":tcph[5]}	 
	    h_size = iph_length + tcph_length * 4
	    data_size = len(packet) - h_size
	    #get data from the packet
	    data = packet[h_size:] 
	    # check if the packet is duplicate 
	    dup_check = check_dup_packet(iph[3])

	    #update the time the last packet from destination was observed
	    global last_packet_time 
	    last_packet_time = datetime.now() 
	    # for parsing data, check if data is part of the packet	
	    if data_enabled != 1:
	    	if(data.find("\r\n\r\n") != -1):
	    		#print(data)
		    	global data_enabled 
		    	data_enabled = 1

		update_congestion_window()
		# create a dictionary for a packet with its IP header, TCP header and data
	    packet_dict={"ip_header" : ip_dict, "tcp_header" : tcp_dict, "data": data}	

	    # check if the packet is in order or not 		
	    if dup_check !=1 and packet_dict["ip_header"]["source"]== dest_ip and packet_dict["tcp_header"]["dest_port"] == tcp_source:
		if (check_tcp_checksum(tcp_header,data) or  check_ip_checksum(iph)):
		    	packets_list.append(packet_dict)
				

def process_packets():

	print(tcp_source)
	while (not fin_flag or len(packets_list)>0): # fin flag not set and list has packets 
		#get the packet with the next sequence number
		i = get_next_packet()
		# retransmit acknowlegement for the packets if not received within one minute
		if (not i and  len(packets_list) !=0 and (current_time - last_packet_time).total_seconds() > 60 ):
			retransmit_ack()
				
		elif i:	
			#if SYN-ACK then send an ACK
			if(i["tcp_header"]["flags"] == 18):
				#update_data_acked(i["tcp_header"]["sequence"])

				#drop packet from sent_packets list if it an ack was recived for it 
				drop_sent_packet(i['tcp_header']['ack'] -1)	#ghost byte 
				#send an ack for the packet received
				send_ack_get(i)
				#remove packet from the packets_list and add it to process_list
				packets_list.remove(i)
				update_data_acked(i["tcp_header"]["sequence"])	
				processed_list.append(i)
			# if fin or psh/fin
			elif(i["tcp_header"]["flags"] == 17 or i["tcp_header"]["flags"] == 25):
				#in case of PSH
				if(len(i["data"]) > 0):
					write_to_file(i["data"])
				#send back fin	
				send_fin(i)
				global fin_flag
				fin_flag = 1
				#remove packet from the packets_list and add it to process_list
				packets_list.remove(i)	
				update_data_acked(len(i["data"]))
				processed_list.append(i)
			#if psh-ack/ack then store data  
			elif(i["tcp_header"]["flags"] == 24 or i["tcp_header"]["flags"] == 16):
				drop_sent_packet(i['tcp_header']['ack'])	
				if(len(i["data"]) > 0):
					write_to_file(i["data"])
					send_ack(i)
				packets_list.remove(i)	
				update_data_acked(len(i["data"]))
				processed_list.append(i)
		
	os._exit(0)	

# Method to drop packets from sent_packets list
def drop_sent_packet(ack_no):
	for i in sent_packets:		
		if i["sequence"]  == ack_no :	
			sent_packets.remove(i)

# check if sent packets need to be resent if an ack is not received within 1 minute		
def check_resend_packets():
	for i in sent_packets:
		if((current_time - i["sent_time"]).total_seconds() > 60):
				retransmit_sent_pckt(i["packet"])
				i["sent_time"]=datetime.now()
				#print("sent packet again")

# retransmit packet
def retransmit_sent_pckt(packet):
	s.sendto(packet, (dest_ip , 0 ))

# Method to check if the packet recieved is a duplicate packet
def check_dup_packet(packet_num):
	for i in processed_list:
		if (packet_num == i["ip_header"]["ip_id"]):
			return 1	
	return 0

# Gets the next packet based on data acknowledged (returns 0 if the required packet is not found)
def get_next_packet():	
	
	for i in packets_list:
		if (data_acked + 1 == i["tcp_header"]["sequence"] or i["tcp_header"]["flags"]==18):
			return i 		
	return 0

#updates the data that has been acknowledged 
def update_data_acked(data_len):
	global data_acked
	data_acked += data_len

# Method to write to the file 
def write_to_file(data):
	pos = data.find("\r\n\r\n")
	if pos != -1:
		data = data[pos+4:] 
	if data_enabled == 1 and data.find("HTTP/1") == -1:
		f = open(file_name,'a+')
		f.write(data)
		f.close	

def retransmit_sent_pcktack():
	update_tcp_flags(0,0,0,0,1,0)
	#send ack
	s.sendto(packet, (dest_ip , 0 ))

# Method to send ack for the received data
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

# Sends fin to tear down the connection 			
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

# Send an ack ang get reuest to reuest for the data 
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
	user_data = get_request(path)
	update_tcp_flags(0,0,0,1,1,0)
	tcp_header = get_tcpheader()
	ip_header = get_ipheader()
	packet = ip_header + tcp_header + user_data	

	# append the packet int the sent_packets list 
	packet_dict = {"sent_time" : datetime.now(), "sequence" : tcp_seq + len(user_data), "packet": packet}
	sent_packets.append(packet_dict)

	s.sendto(packet, (dest_ip , 0 ))
	
#updates TCP flag fields based on the TCP flag to be sent 
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

#updates TCP flags based on the TCP flag to be sent
def update_seq_ack(seq,ack):
    global tcp_seq
    tcp_seq = seq
    global tcp_ack_seq
    tcp_ack_seq = ack

# Method to create IP header
def get_ipheader():
   
    global ip_check
    ip_check=0	
    #increment the packet id 	
    global ip_id 
    ip_id+=1 
    
     			
    #calculate version+ ihl byte	
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
	
    # calculate total length
    ip_tot_len = sys.getsizeof(tcp_header+user_data)
    
    # the ! in the pack format string means network order(with 0 checksum)
    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,ip_saddr, ip_daddr)
	
    #recompute checksum
    ip_check = compute_header_checksum(ip_header)
    
    ip_header_check = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,ip_saddr, ip_daddr)
    return ip_header_check


# Method to create TCP header 
def get_tcpheader():
    global tcp_check
    tcp_check = 0
    global tcp_flags
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

#Recomputes TCP checksum to verify with the received checksum
def check_tcp_checksum(tcph,data):
	tcp_check_recvd = unpack('H' , tcph[16:18])
	tcp_header_16 = unpack('!HHLLBBH' , tcph[0:16])
	tcp_header_offset = unpack('!H', tcph[18:20])
	tcp_header = pack('!HHLLBBHHH', tcp_header_16[0],tcp_header_16[1], tcp_header_16[2], tcp_header_16[3], tcp_header_16[4], tcp_header_16[5],tcp_header_16[6], 0, tcp_header_offset[0])
	
	source_address = socket.inet_aton(source_ip)
	dest_address = socket.inet_aton(dest_ip)
	placeholder = 0
	protocol = socket.IPPROTO_TCP
	tcp_length = len(tcp_header) + len(data)

	psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
	psh = psh + tcp_header + data;
	tcp_check = checksum(tcp_header)
		
	return tcp_check_recvd[0]==tcp_check

#Recomputes IP checksum to verify with the received checksum	
def check_ip_checksum(iph):
	ip_check_recvd = iph[7]
	ip_header = pack('!BBHHHBBH4s4s', iph[0], iph[1], iph[2], iph[3], iph[4], iph[5], iph[6], 0, iph[8], iph[9])	
	ip_check = compute_header_checksum(ip_header)
	return ip_check_recvd==ip_check

#Updates congestion window based on the packets received
def update_congestion_window():
	global congestion_window
	if congestion_window <1000:
		congestion_window+=1

# Computes IP checksum
def compute_header_checksum(header):
		
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

#Computes TCP checksum 
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

# Forms the get request
def get_request(path):
	create_file(path)
	return "GET "+path+" HTTP/1.0\r\n\r\n"

#creates an empty file based on the path 
def create_file(path):
	global file_name
	pos = path.rfind("/")
	if len(path) > pos + 1:
		file_name = path[pos+1:]
	else :
		file_name = "index.html" 
	f =open(file_name,"w+")

#checks if sent packets need to be resent and also terminates the connection if no packet is recieved from the 
# destination in 3 minutes
def check_timeout():
	global current_time
	current_time = datetime.now()
		
	while ((current_time - last_packet_time).total_seconds() < 180):
		current_time = datetime.now()
		check_resend_packets()
	os._exit(0)
##########################################################################################################################
##########################################################################################################################

# get command line arguments 
if len(sys.argv) < 2:  
	print("Usage : ./rawhttpget [URL]")
	sys.exit(1)
# set host and path
url_parsed = sys.argv[1].rpartition("//")
pos = url_parsed[2].find("/")
host = url_parsed[2][:pos]
if host.find("www") != -1:
	host_pos = host.find("www")
	host = host[host_pos + 4:]

path = url_parsed[2][pos:]
print (host, path)


sent_packets = [] #list to store sent packets
packets_list = [] #list to store received packets
processed_list = []# list to store processed packets

source_ip = '10.0.2.15' 
dest_ip = socket.gethostbyname(host)
#print("dest ip :" + dest_ip)
data_acked = 0
#file_name = ""
fin_flag = 0
last_packet_time = datetime.now()
current_time = datetime.now()
data_enabled = 0
congestion_window = 1

#ip header fields 
ip_ihl = 5
ip_ver = 4
ip_tos = 0  #precedence[0-2],delay[3], throughput[4],reliability[5], Reserved[6-7]
ip_tot_len = 0  
ip_id = 196  # Id of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_TCP
ip_check = 0  
ip_saddr = socket.inet_aton(source_ip)  
ip_daddr = socket.inet_aton(dest_ip)

#tcp header fields 

tcp_source = random.randint(1200, 5000)# source port
tcp_dest = 80   # destination port
tcp_seq = 1234	#randomly selected sequence
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
#form flags
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)


# create a receiver thread
threading.Thread(target=receive_packets).start()

# create a processing thread 
threading.Thread(target=process_packets).start()

# create a timeout thread
threading.Thread(target=check_timeout).start()

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

# append the packet int the sent_packets list 
packet_dict={"sent_time" : datetime.now(), "sequence" : tcp_seq + len(user_data), "packet": packet}
sent_packets.append(packet_dict)

s.sendto(packet, (dest_ip , 0 )) 
##############################################################################################################################
##############################################################################################################################
