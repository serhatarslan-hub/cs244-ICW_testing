#!/usr/bin/python

"""
Measure Initial Congestion Window of URLs given
"""

from argparse import ArgumentParser
import random
from scapy.all import *

# Global variables to match retransmissions
cur_seqno = 0
prev_seqno = 0
ip_of_url = None
# Global variable to set timeouts on transmissions
t_out = 10

def readList(filename):
	url_list = []
	with open(filename) as f:
		for line in f:
			split_line = line.split()
			if(split_line):
				url_list.append( split_line[0] )
	return url_list

def update_stream(packet):
	global cur_seqno, prev_seqno
	prev_seqno = cur_seqno
	cur_seqno = packet.seq

def stop_stream(packet):
	global cur_seqno, prev_seqno, ip_of_url
	FIN = 0x01
	F = packet['TCP'].flags
	
	if( packet['IP'].src!=ip_of_url or 
		( packet.seq< prev_seqno or (F & FIN) ) ):
		# Response from a different source,
		# Retransmission or FIN packet
		return True
	else:
		return False


# TODO: maybe try first the main page, then try this
def get_long_str():
	'''
	Generate a very long arbitrary string that increases the url length,
	so that the response is large too.
	'''
	short_str = 'AAAAAaaaaaBBBBBbbbbbCCCCCcccccDDDDDdddddEEEEEeeeee'
	long_str = short_str
	for _ in range(26):
		long_str = long_str + short_str
	return long_str

def send_syn(url,rsport,mss):
	global t_out, ip_of_url
	try:
		syn = IP(dst=url)/TCP(sport=rsport, dport=80,flags='S',seq=1,
				options=[('MSS',mss)])
	except:
		print("-> Could not create the SYN packet")
		return None

	ans, _ = sr(syn, timeout=t_out)
	if(ans):
		ip_of_url = ans[0][1].src
		#print("** ",url," replied from: ",ip_of_url)
		return ans[0][1]
	else:
		return None

def send_request(url,syn_ack):
	global cur_seqno, prev_seqno, t_out
	cur_seqno = 0
	prev_seqno = 0
	long_str = get_long_str()

	getStr = 'GET /'+long_str+' HTTP/1.1\r\nHost: '
	getStr += url+'\r\nConnection: Close\r\n\r\n'
	get_rqst = IP(dst=syn_ack.src)/TCP(dport=80, sport=syn_ack.dport, 
				seq=syn_ack.ack, ack=syn_ack.seq + 1, flags='A') / getStr

	send(get_rqst)
	# prn function takes effect and acts on the packet every step of the way
	# stop_filter
	packets = sniff(filter='tcp src port 80', prn=update_stream, 
				timeout=t_out, stop_filter=stop_stream)
	
	return packets, get_rqst

def send_rst(request):
	global prev_seqno

	rst = IP(dst=request['IP'].dst)/TCP(dport=80, sport=request.sport, 
				seq=request.seq + len(request['TCP'].payload),
				ack=prev_seqno + 1, flags='R')

	send(rst)

def get_icw(responses,mss):
	global ip_of_url
	seen_seqno = 0
	icw = 0
	FIN = 0x01
	
	for pkt in responses:
		segment_size = len(pkt['TCP'].payload)
		pad = pkt.getlayer(Padding)
		F = pkt['TCP'].flags

		if(pad):
			segment_size -= len(pad)
		
		if (pkt['IP'].src != ip_of_url):
			# Server responds from different source(s)
			continue
		elif (segment_size == 0 and not(F & FIN)):
			# Empty packet 
			continue
		elif ((segment_size != mss) or (F & FIN)):
			# Either not a full packet or a FIN packet
			# ICW test fails
			return 0
		else:
			if(seen_seqno < pkt.seq):
				seen_seqno = pkt.seq
				icw += 1	
	return icw

def main():

	url_list = readList(args.url_list)
	pcap_file = 'reproduction.pcap'

	# Some linux servers will automatically make it 64 per min, but 48 is safe
	mss = 48
	
	for url in url_list:
		print("*** ",url)
		# TODO: loop over them insted
		# Start from 65k and go down
		rsport = random.randrange(2048,65500)

		syn_ack = send_syn(url,rsport,mss)
	
		if(syn_ack):
			if (syn_ack.sprintf("%TCP.flags%")=='SA'):
			
				responses, request = send_request(url,syn_ack)
				icw = get_icw(responses,mss)
				send_rst(request)

				wrpcap(pcap_file,responses)
				print("** ICW for ",url,": ",icw)
				
		else:
			print("-> Could not get a SYN-ACK response")

if __name__ == "__main__":

	parser = ArgumentParser()
	parser.add_argument('--url_list', help="File that contains the list of URLS to be measured", required=True)
	args = parser.parse_args()

	main()
 
