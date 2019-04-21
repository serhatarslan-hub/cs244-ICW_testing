#!/usr/bin/python
from argparse import ArgumentParser
from icw_test import ICWTest, Result
import numpy as np
import os


def read_url_list(filename):
    with open(filename, "r") as f:
        return [line.split()[0] for line in f]


def main():
    parser = ArgumentParser()
    parser.add_argument('--url_list', type=str, required=True,
                        help="File that contains the list of URLs to measure.")
    # parser.add_argument('--url', type=str,
    #                     help="")
    args = parser.parse_args()

    urls = read_url_list(args.url_list)
    print("Performing ICW test on %d URLs." % len(urls))

    # Some linux servers will automatically make it 64 per min, but 48 is safe
    mss = 48

    # Loop over ports from 2048 to 65500 in a random order
    ports = np.random.permutation(np.arange(2048, 65500))

    for url, rsport in zip(urls, ports):
        print("="*32)
        print("Testing: %s on port %d" % (url, rsport))

        # Block the OS kernel from processing packets on this port
        try:
            os.system("iptables -t raw -A PREROUTING -p tcp --dport %d -j DROP"
                      % rsport)
        except:
            print("==> Failed to set up firewall rule. Make sure iptables is\n"
                  "    set up correctly.")
            return

        try:
            experiment = ICWTest(url=url)
            result, icw = experiment.run_test(
                mss=mss, rsport=rsport, pcap_output='debug.pcap')
            if result == Result.SUCCESS:
                print("==> Result: success!\n==> ICW Estimate: %d" % icw)
            else:
                print("==> Result: error: %s" % result)
        finally:
            # Undo firewall rule
            os.system("iptables -t raw -D PREROUTING -p tcp --dport %d -j DROP"
                      % rsport)
        

if __name__ == "__main__":
    main()
