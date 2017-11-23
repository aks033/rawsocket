#Packet sniffer in python for Linux
#Sniffs only incoming TCP packet
 
import socket, sys
from struct import *

packets_list =[]
 
#create an INET, STREAMing socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
 
# receive a packet
while True:
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
    
   # ip_tos = iph[1]
   # ip_tot_len = iph[2]
     
    iph_length = ihl * 4	
   # ip_id = iph[3]  # Id of this packet
   # ip_frag_off = iph[4]
   # ttl = iph[5]
   # protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);
    
    ip_dict = {"ihl" : ihl, "version" : version, "tos" : iph[1], "total_length" : iph[2], "ip_id" : iph[3], "ip_frag_off" : iph[4], "ttl" : iph[5], "protocol" : iph[6], "source" : s_addr,"destination" : d_addr}

    for index in ip_dict:
    	print index + " : " + str(ip_dict[index])	

     
    #print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
     
    tcp_header = packet[iph_length:iph_length+20]
     
    #now unpack them :)
    tcph = unpack('!HHLLBBHHH' , tcp_header)
     
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    print("-----------------------------------------------------------------------------------------------------------------------------------")
    tcp_dict = {"source_port " : tcph[0], "dest_port" : tcph[1], "sequence": tcph[2], "acknowledgement":acknowledgement, "length":tcph_length}
    for index in tcp_dict:
    	print index + " : " + str(tcp_dict[index])	
     
    #	print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
    print("-----------------------------------------------------------------------------------------------------------------------------------")
    print("-----------------------------------------------------------------------------------------------------------------------------------")
    h_size = iph_length + tcph_length * 4
    data_size = len(packet) - h_size
     
    #get data from the packet
    data = packet[h_size:]
     
    print 'Data : ' + data
    
    packet_dict={"ip_header" : ip_dict, "tcp_header" : tcp_dict, "data": data}

    for index in packet_dict:
    	print index + " : " + str(packet_dict[index]["tcp_header"][sequence])

	
    if packet_dict["ip_header"]["source"]== "104.20.37.43":
    	packets_list.append(packet_dict) 
    
    print(packets_list)
