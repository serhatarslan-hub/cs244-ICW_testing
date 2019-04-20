#!/usr/bin/python
from argparse import ArgumentParser
from icw_test import ICWTest
import random

def readList(filename):
    url_list = []
    with open(filename) as f:
        for line in f:
            split_line = line.split()
            if(split_line):
                url_list.append( split_line[0] )
    return url_list

def main():
    parser = ArgumentParser()
    parser.add_argument('--url_list',
                        help="File that contains the list of URLs to measure.",
                        required=True)
    args = parser.parse_args()

    url_list = readList(args.url_list)
    pcap_file = 'reproduction.pcap'

    # Some linux servers will automatically make it 64 per min, but 48 is safe
    mss = 48
    
    for url in url_list:
        print("*** ",url)
        # TODO: loop over ports insted
        # Start from 65k and go down
        rsport = random.randrange(2048, 65500)

        experiment = ICWTest(url=url)
        experiment.run_test(mss=mss, pcap_output='reproduction.pcap',
                            rsport=rsport)

if __name__ == "__main__":
    main()