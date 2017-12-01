#############################
#### High Level Approach: ###
#############################
	Created following methods:
		receive_packets(): Thread to recieve packets from the destination and storing the packets in the packets_list based on various checks.
		process_packets(): This method continuously processes the packets in packets_list and sends reply packets based on the flags of the recieved packets. 
		drop_sent_packet(ack_no): This method drops the sent packets for which ana acknowledgement has been recieved. 
		check_dup_packet(packet_num): checks if duplicate packets are recieved. 
		get_next_packet(): Fetches the next packet in packets_list based on sequence number.
		write_to_file(data): To write data recieved in packets to the file
		retransmit_ack(): Method to retransmit acknowlegement if the packet with the next sequence number is not recieved. 
		send_ack(packet): Send acknowledgement for the recieved packets.
		send_fin(packet): Send fin to terminate the communication with the destination 
		send_ack_get(packet): Sends the get request to the destination.
		update_tcp_flags(fin,syn,rst,psh,ack,urg): Updates flags before forming the TCP headers.
		update_seq_ack(seq,ack): Updates the sequence number and acknowledgement before forming the TCP header
		get_ipheader(): Forms the IP header
		get_tcpheader(): Forms the TCP header
		check_tcp_checksum(tcph,data): Checks the TCP checksum of the recieved packets
		check_ip_checksum(iph): Checks the IP checksum of the recieved packets
		compute_header_checksum(header): Computes checksum for the IP header
		checksum(message): Computes checksum for the TCP header
		get_request(path): Forms the get request to be sent to the destination to get the html or other form of information.
		create_file(path): Creates the file to write data into.
		check_timeout(): Keeps a constatnt check on the recieved packet and terminates the process if no packets are recieved for 3 minutes.


		Approach:
		- At start a SYN packet is sent to the destination and a packet-receiving thread and a packet-processing thread starts.
		- Receiving thread keeps adding packets to the packets_list and drops all the duplicate packets received. 
		- The packets in the packets_list is stored in the form of a dictionary("ip_header","data","tcp_header").
		- The processing thread processes the packets and sends responses, if the fin_flag is not set and the packets_list is not empty. The packets get processed based on the sequence number maintained by the destination and the data acknowledged at our end. 
		- Based on the tcp header flags the following actions take place:
			- SYN-ACK : On receiving SYN-ACK the programs sends n ACK along with the get request to request for data.
			- ACK/PSH-ACK : If an ACK comes for a sent packet, that packet is dropped from the sent packets list and considered delivered. In case of PSH-ACK, if data is received it is stored in the file.
			- FIN-ACK : a FIN packet is sent to terminate the connection. The program runs if there are unprocessed packets in the list even after FIN-ACK is received.

		Timeouts :
		-If ACK for a sent packet is not received within 1 minute of being sent, the packet will be retransmitted.
		-If packet with the next expected sequence is not recieved within a minute, then an ACK is sent again.
		-A timeout thread constantly checks the difference between the last recieved packet and current time. If there is no packet transfer from the destination IP, then the program closes within 3 minutes 	

		Window:
		An advertised window of size 	
#############################
### Challenges Faced: #######
#############################
	- Figuring out how to receive packets using raw sockets and understanding headers.  
	- computing IP checksum 
	- packing/unpacking headers
	-  

#############################
####### How to run: #########
#############################
	./rawhttpget [URL]