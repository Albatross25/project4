from struct import *
import random, socket , sys, time,os

#function to calculate checksum
def checksum(msg):
	    sum = 0

	    # loop taking 2 bytes at a time
	    for i in range(0, len(msg), 2):
	        bit_16 = ord(msg[i]) + (ord(msg[i+1]) << 8 )
	        sum = sum + bit_16

	    sum = (sum>>16) + (sum & 0xffff); # adding the carry to the sum
	    sum = sum + (sum >> 16);# adding the carry to the sum

	    #complement and mask to 4 byte short
	    sum = ~sum & 0xffff
	    return sum

#class to construct IP and TCP header with checksum
class packet_send():
	def tcp_header(self,syn, ack, psh,fin,seq_num7,ack_num7,data,mss,win_size1):
		self.mss= mss
		if self.mss==33818036: # setting the MSS to 1460 bytes in the SYN request
			self.offset=6 # header length will be 24 bytes with options feild with MSS
		else:
               		 self.offset = 5 # header lengthh will be 20 bytes without options feild used
		self.seq_num1=seq_num7
		self.ack_num1=ack_num7
                self.offset_reserved = (self.offset << 4)+0
                self.fin = fin
                self.syn = syn
                self.rst = 0
                self.psh = psh 	
                self.ack = ack
                self.urg = 0
                self.window = win_size1   
                self.tcp_checksum = 0
                self.urg_ptr = 0
                self.flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh <<3) + (self.ack << 4) + (self.urg << 5)
                if self.mss==33818036:
			 self.tcp_header1 = pack('!HHLLBBHHHL' , source_port, dest_port,self.seq_num1, self.ack_num1, self.offset_reserved, self.flags,  self.window, self.tcp_checksum, self.urg_ptr,self.mss)
		else:
                         self.tcp_header1 = pack('!HHLLBBHHH' , source_port, dest_port,self.seq_num1, self.ack_num1, self.offset_reserved, self.flags,  self.window, self.tcp_checksum, self.urg_ptr)		

		self.payload = data
        #pseudo header
		self.source_address = socket.inet_aton( source_ip )
		self.dest_address = socket.inet_aton(dest_ip)
		self.reserved = 0
		self.protocol = socket.IPPROTO_TCP
		if self.payload!=0:
			self.tcp_length = len(self.tcp_header1)+len(self.payload)
			self.pseudo_header = pack('!4s4sBBH' , self.source_address , self.dest_address , self.reserved , self.protocol , self.tcp_length)
			self.pseudo_header = self.pseudo_header + self.tcp_header1+self.payload
		else:
			self.tcp_length = len(self.tcp_header1)
                        self.pseudo_header = pack('!4s4sBBH' , self.source_address , self.dest_address , self.reserved , self.protocol , self.tcp_length)
                        self.pseudo_header = self.pseudo_header + self.tcp_header1
		self.tcp_checksum = checksum(self.pseudo_header)
		if self.mss==33818036:
			self.tcp_header1 = pack('!HHLLBBH', source_port, dest_port,self.seq_num1, self.ack_num1, self.offset_reserved, self.flags,  self.window)+pack('H' , self.tcp_checksum)+pack('!HL' , self.urg_ptr, self.mss)
		else:
			self.tcp_header1 = pack('!HHLLBBH', source_port, dest_port,self.seq_num1, self.ack_num1, self.offset_reserved, self.flags,  self.window)+pack('H' , self.tcp_checksum)+pack('!H' , self.urg_ptr)
		return self.tcp_header1

#function for building IP header
	def ip_header(self):
                self.ip_ihl = 5
                self.ip_ver = 4
                self.ip_tos = 0
                self.ip_tot_len = 20+len(self.tcp_header1)
                self.ip_id = random.randint(50000,60000) #Id of this packet
                self.ip_flag_df = 1
                self.ip_flag_mf = 0
                self.ip_frag_off = 0
                self.ip_ttl = 255
                self.ip_proto = socket.IPPROTO_TCP
                self.ip_check = 0
                self.ip_saddr = socket.inet_aton ( source_ip )
                self.ip_daddr = socket.inet_aton ( dest_ip )
                self.ip_flags = (((self.ip_flag_df << 1) + self.ip_flag_mf) << 13) + self.ip_frag_off
                self.ip_ihl_ver = (self.ip_ver << 4) + self.ip_ihl
                
                # the ! in the pack format string means network order
                self.ip_header = pack('!BBHHHBBH4s4s' , self.ip_ihl_ver, self.ip_tos, self.ip_tot_len, self.ip_id, self.ip_flags, self.ip_ttl, self.ip_proto, self.ip_check, self.ip_saddr, self.ip_daddr)
                #print len(ip_header)
                self.ip_check = checksum(self.ip_header)
                self.ip_header_new = pack('!BBHHHBB', self.ip_ihl_ver, self.ip_tos, self.ip_tot_len, self.ip_id, self.ip_flags, self.ip_ttl, self.ip_proto) + pack('H', self.ip_check) + pack('!4s4s', self.ip_saddr,self.ip_daddr)
                #print self.ip_check
                return self.ip_header

#fucnction for sending syn,ack requests to server
def handshake(syn,ack,psh,fin,seq_num6,ack_num6,win_size,mss=33818036):
                x=packet_send() # class for constructing TCP and IP header
		data=0
                mss1=mss
                if mss1==0:
                        tcp=x.tcp_header(syn,ack,psh,fin,seq_num6,ack_num6,data,mss1,win_size)
                else:
                        tcp=x.tcp_header(syn,ack,psh,fin,seq_num6,ack_num6,data,mss1,win_size)
                packet = ''
		ip=x.ip_header()
                packet =ip+tcp
                return packet
#function for sending data,fin requests to server
def data_connection(ack,psh,fin,seq_num5,ack_num5,win_size,data=''):
                x=packet_send()
            
                if len(data) % 2 == 1:# data padded with 0 to make the length even
                        data += "0"
                mss=0
		syn=0
                tcp=x.tcp_header(syn,ack,psh,fin,seq_num5,ack_num5,data,mss,win_size)
                packet = ''
		ip=x.ip_header()
                packet = ip+tcp+data
                return packet
#function to receive syn ack response from server
def recv(bytes=65565):
                start = time.time()
                time.clock()
                elapsed = 0
                while elapsed < 180:
                        elapsed = time.time() - start
                        packet = r.recvfrom(bytes)# receives the SYN ACK response from server
                        ip = packet[1][0]
                        if ip == dest_ip:# checking if the packet is for the correct source ip
                                 packet=packet[0]
                                 p=unpack('!HHLLBBHHH', packet[20:40]) # unpacks the header to extract feilds
                                 if p[1]==source_port:
                                        return p
#function to receive the data from server
def recv_page(expected_ack, expected_seq):
	cwnd=1
	seq_recv = []
	ack_num_sent=0
        while True:
        	packet_recv = r.recvfrom(65565)
        	packet = packet_recv[0]
		ip=packet_recv[1][0]
		ip_header=packet[0:20]
		ip_check=checksum(ip_header) # check the IP header checkum it should be 0
        	tcp_header = packet[20:40]
        	tcp_h = unpack("!HHLLBBHHH" , tcp_header)
		dest_port = tcp_h[1]
		seq_num_data = tcp_h[2]
		ack_num_data = tcp_h[3]
		doff_reserved = tcp_h[4]
		win_size=tcp_h[6]
        	tcp_length = doff_reserved >> 4
        	tcp_flag = tcp_h[5]
		header_size = 20 + tcp_length * 4
        	data_size = len(packet) - header_size
        	data = packet[header_size:]         
		if dest_port == source_port:
			pass
			if dest_ip == ip:# check if packet is for this particular client
				pass
				if ack_num_data==expected_ack+1 or ack_num_data==expected_ack: # check the received ack number,with the expected ack
					pass
					if tcp_flag == 16 and cwnd<=1000: #check if ack flag is set
						cwnd+=1

					elif tcp_flag == 24 and cwnd<=1000:#check if PSH and ACK flag is set
						if seq_num_data in seq_recv:
							pass							
							#check for duplicate packets
						else:
							#seq_recv.append(seq_num_data)
							cwnd+=1
							header_size = 20 + tcp_length * 4
        	                        		data_size = len(packet) - header_size
                	                		data = packet[header_size:]
							#http_data[seq_num_data] = data
			                                if seq_num_data==(y+1) or seq_num_data==ack_num_sent:
								seq_recv.append(seq_num_data)
                                #data_length.append(data_size)
                        	        			http_data[seq_num_data] = data
								ack_num_sent=seq_num_data+len(data)
								packet_send_data=data_connection(1,0,0,ack_num_data,ack_num_sent,win_size)
								s.sendto(packet_send_data, (dest_ip ,0))
                               				else:
                              					  packet_send_data=data_connection(1,0,0,ack_num_data,ack_num_sent,win_size)
                                				  s.sendto(packet_send_data, (dest_ip ,0))
								

					elif tcp_flag == 25 or tcp_flag == 17:#check if FIN flag is set, exit loop after senfing FIN response
						cwnd+=1
						header_size = 20 + tcp_length * 4
                                		data_size = len(packet) - header_size
                                		data = packet[header_size:]
						http_data[seq_num_data] = data
                                                packet_send_data=data_connection(1,0,1,ack_num_data,seq_num_data+len(data)+1,win_size)
                                                s.sendto(packet_send_data, (dest_ip ,0))
						if tcp_flag % 2 != 0:
							break 
					else:
						cwnd=1
	
	return http_data
#function to write data to a file
def writeData(http_data):
        s=''
        string=''
        for key, value in sorted(http_data.items()):
	    s=str(value)
            if s.startswith('HTTP'):
		status_code=s.split()[1]
		if status_code=='200':
                	string=string+s.split("\r\n\r\n", 1)[1]
		else:
		  print "Error response from server"
            else:
                string=string+s
        try:
            f1.write(string)
	    print "file successfully downloaded"
            f1.close()
        except error:
            print ' Could not write to file'
            sys.exit()

#Main program
os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
try:
        url=sys.argv[2]
        source_ip=sys.argv[1]

except IndexError:

        print "wrong format, Enter in format : ./rawhttpget [url]"
        sys.exit()
http_data=dict()
#the url is parsed to get the host name
parse= url.split('/')
#if no path or / at end use index.html
if parse[len(parse)-1]=='' or len(parse)==3 :
       f1=open('index.html','w')

#if html page name specified in url, use that file name
else:
        filename= parse[len(parse)-1]
        f1=open(filename,'w')

host=parse[2]
dest_ip =  socket.gethostbyname('%s' %host)
source_port=random.randint(50000,65535)
#print source_port
#create a raw socket to send
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
#create a raw socket to receive
try:
    r = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

except socket.error , msg:
    print 'receive Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()


dest_port=80 #HTTP server port
source_address = socket.inet_aton(source_ip)
dest_address = socket.inet_aton(dest_ip)
seq_num=random.randint(222222,333333)
ack_num=0
packet_send_syn=handshake(1,0,0,0,seq_num,ack_num,65535)
s.sendto(packet_send_syn, (dest_ip , 0 ))
p=recv()
seq_num2=p[3]
ack_num2=p[2]+1
window_size=p[7]
packet_send_ack=handshake(0,1,0,0,seq_num2,ack_num2,window_size,0)
s.sendto(packet_send_ack, (dest_ip , 0))
y=p[2]
HTTP_header='GET %s HTTP/1.0\r\nHost: %s\r\n\r\n' %(url,host)
packet_send_data=data_connection(1,1,0,seq_num2,ack_num2,window_size,HTTP_header)
s.sendto(packet_send_data, (dest_ip ,0))
expected_ack=seq_num2+len(HTTP_header)
expected_seq=ack_num2
http_data=recv_page(expected_ack,expected_seq)
writeData(http_data)

