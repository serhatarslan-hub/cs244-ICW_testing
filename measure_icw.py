#!/usr/bin/python

"""
Measure Initial Congestion Window of URLs given
"""

from argparse import ArgumentParser
import random
from scapy.all import *

seqno = 0

def readList(filename):
	
	url_list = []
	
	with open(filename) as f:
		for line in f:
			split_line = line.split()
			if(split_line):
				url_list.append( split_line[0] )
	return url_list

def update_stream(packet):
	#print(packet.seq)
	global seqno
	seqno = packet.seq

def stop_stream(packet):
	global seqno
	print("Packet seqno:",packet.seq," Global seqno:",seqno)
	if( packet.seq< seqno ):
		print("Returning True")
		return True
	else:
		print("Returning False")
		return False

def get_long_str():
	short_str = 'AAAAAaaaaaBBBBBbbbbbCCCCCcccccDDDDDdddddEEEEEeeeee'
	long_str = short_str
	for _ in range(26):
		long_str = long_str + short_str
	return long_str

def main():

	url_list = readList(args.url_list)
	pcap_file = 'reproduction.pcap'

	mss = 64
	recv_wnd = 65500
	long_str = get_long_str()

	for url in url_list:
		print(url)
		rsport = random.randrange(2048,65500)

		syn = IP(dst=url)/TCP(sport=rsport, dport=80,flags='S',seq=1,
			options=[('MSS',mss)])
		ans, unans = sr(syn)
		syn_ack = ans[0][1]	
		if (syn_ack.sprintf("%TCP.flags%")=='SA'):
			
			getStr = 'GET /'+long_str+' HTTP/1.1\r\nHost: '+url+'\r\nConnection: Close\r\n\r\n'
			get_rqst = IP(dst=syn_ack.src)/TCP(dport=80, sport=syn_ack.dport, 
					seq=syn_ack.ack, ack=syn_ack.seq + 1, 
					flags='A', window = recv_wnd) / getStr
			#rep, unans = sr(get_rqst)
			global seqno
			seqno = 0
			send(get_rqst)
			packets = sniff(filter='tcp src port 80',
					prn=update_stream, timeout=10,
					stop_filter=stop_stream)
			wrpcap(pcap_file,packets)
			print(len(packets))

if __name__ == "__main__":

	parser = ArgumentParser()
	parser.add_argument('--url_list', help="File that contains the list of URLS to be measured", required=True)
	args = parser.parse_args()

	main()
 
