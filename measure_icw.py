#!/usr/bin/python

"""
Measure Initial Congestion Window of URLs given
"""

from argparse import ArgumentParser
from scapy.all import *

def readList(filename):
	
	url_list = []
	
	with open(filename) as f:
		for line in f:
			split_line = line.split()
			if(split_line):
				url_list.append( split_line[0] )
	return url_list

def main():

	url_list = readList(args.url_list)
	pcap_file = 'reproduction.pcap'

	mss = 16
	recv_wnd = 65500
	
	
	for url in url_list:
		syn = IP(dst=url)/TCP(dport=80,flags='S',
			options=[('MSS',mss)], window = recv_wnd)
		ans, unans = sr(syn)
		syn_ack = ans[0][1]	
		if (syn_ack.sprintf("%TCP.flags%")=='SA'):
			ack = IP(dst=url)/TCP(dport=80,flags='A',
				options=[('MSS',mss)], window = recv_wnd)
			sr(ack)

			getStr = 'GET / HTTP/1.1\r\nHost: '+url+'\r\n\r\n'
			get_rqst = IP(dst=url)/TCP(dport=80, sport=syn_ack.dport, 
					seq=syn_ack.ack, ack=syn_ack.seq + 1, 
					flags='A',options=[('MSS',mss)], 
					window = recv_wnd) / getStr
			rep, unans = sr(get_rqst)
			print rep[0]
		


if __name__ == "__main__":

	parser = ArgumentParser()
	parser.add_argument('--url_list', help="File that contains the list of URLS to be measured", required=True)
	args = parser.parse_args()

	main()
 
