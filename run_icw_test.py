#!/usr/bin/python
import numpy as np
import os
from argparse import ArgumentParser
from icw_test import ICWTest, Result
from collections import defaultdict
import socket

def read_url_list(filename):
    with open(filename, "r") as f:
        return [line.split()[0] for line in f]


def print_table_2(categories):
    """
    Print the results in Table 3 (Section 4.1)
    """
    print("Table 2: ICW: Server categories")
    print("+-----------+----------------+")
    print("| Category  | Servers        |")
    print("+-----------+----------------+")
    for i, c in enumerate(categories):
        print(("|         %d |" % (i+1))+"{0: >15}".format(len(c))+ " |")
    print("|     Total |"+"{0: >15}".format(sum([len(c) for c in categories]))+ " |")
    print("+-----------+----------------+")


def print_table_3(categories, icws):
    """
    Only for category 1 URLs, compute and print results in Table 3 (Section 4.1)
    The values in icw[url] are guaranteed to be all the same at this point
    """
    icws = np.array([icws[url][0] for url in categories[0]])
    print("Table 3: ICW: Summary results")
    print("+-----------+----------------+")
    print("| ICW size  | Servers        |")
    print("+-----------+----------------+")
    print("|         1 |"+"{0: >15}".format(np.sum(icws == 1))+ " |")
    print("|         2 |"+"{0: >15}".format(np.sum(icws == 2))+ " |")
    print("|         3 |"+"{0: >15}".format(np.sum(icws == 3))+ " |")
    print("|         4 |"+"{0: >15}".format(np.sum(icws == 4))+ " |")
    print("| 5 or more |"+"{0: >15}".format(np.sum(icws >= 5))+ " |")
    print("|     Total |"+"{0: >15}".format(len(icws))+ " |")
    print("+-----------+----------------+")


def main():
    parser = ArgumentParser()
    parser.add_argument('--url_list', type=str,
                        help="File that contains the list of URLs to measure.")
    parser.add_argument('--host', type=str,
                        help="Host URL or IP address to run the test on")
    parser.add_argument('--debug', action='store_true', default=False,
                        help="If specified, prints the last URL trace to debug.pcap.")
    args = parser.parse_args()

    if args.url_list:
        urls = read_url_list(args.url_list)
        print("Performing ICW test on %d URLs." % len(urls))
    elif args.host:
        urls = [args.host]
    else:
        print("One of --url_list and --host must be specified. (See -h for help.)")
        return

    # "The MSS was set to 100 bytes."
    mss = 100
    num_trials = 5

    # Loop over ports from 2048 to 65500 in a random order
    # in spaces of 5
    ports = np.random.permutation(np.arange(2048, 65500, num_trials))

    # Results becomes a map from URL to 5 trials like
    # {"www.google.com": ["success", "success", "success", "success", "fin"],
    #  "www.apple.com": ["fin", "fin", "fin", "fin", "fin"]
    #  ...}
    # icws becomes a map to 
    results = defaultdict(list)
    icws = defaultdict(list)

    for url, rsport in zip(urls, ports):
        print("="*32)
        
        # Attempt to block port using iptables        
        os.system("iptables -A OUTPUT -p tcp --dport 80 --tcp-flags RST RST -j DROP")

        try:
            # "We tested each server five times."
            for trial in range(num_trials):
                print("\n*** Trial %d ***" % (trial+1))
                print("Testing: %s on port %d" % (url, rsport))
                experiment = ICWTest(url=url)
                result, icw = experiment.run_test(
                    mss=mss, rsport=rsport, pcap_output=('debug.pcap' if args.debug else None))
                if result == Result.SUCCESS:
                    print("==> Result: success!\n==> ICW Estimate: %d" % icw)
                else:
                    print("==> Result: error: %s" % result)
                results[url].append(result)
                icws[url].append(icw)
                rsport += 1
        finally:
            # Undo firewall rule
            os.system("iptables -D OUTPUT -p tcp --dport 80 --tcp-flags RST RST -j DROP")
   
    # Process results to produce categories results for Table 2 (Section 4.1)
    categories = [[], [], [], [], []]
    for url in urls:
        valid_icws = [x for x in icws[url] if x is not None]

        # "If at least three tests return results, and all the results are
        #  the same, the server is added to category 1. We have the
        #  highest confidence in these results, as they have been shown
        #  to be repeatable. We report summary results only for servers
        #  belonging to this category."
        if results[url].count(Result.SUCCESS) >= 3 \
            and all(x == valid_icws[0] for x in valid_icws):
            c = 1

        # "If at least three tests return results, but not all the results are
        #  the same, the server is added to category 2. The differing results
        #  could be due to several factors, such as confusing packet
        #  drop patterns (as discussed in Section 2), which are further
        #  discussed in Section 5. We would like to minimize the number of
        #  servers that fall in this category."
        elif results[url].count(Result.SUCCESS) >= 3 \
            and not all(x == valid_icws[0] for x in valid_icws):
            c = 2

        # "If one or two tests return results, and all the results are the
        #  same, the server is added to category 3. Further tests are
        #  needed to categorize the TCP behavior of this server."
        elif results[url].count(Result.SUCCESS) >= 1 \
            and all(x == valid_icws[0] for x in valid_icws):
            c = 3

        # "If one or two tests return results, and not all the results are
        #  the same, the server is added to category 4. We would like to
        #  minimize the number of servers that fall in this category as
        #  well."
        elif results[url].count(Result.SUCCESS) >= 1 \
            and not all(x == valid_icws[0] for x in valid_icws):
            c = 4

        # "If none of the five tests returned a result, this server was
        #  added to category 5. These servers need to be investigated
        #  further."
        elif results[url].count(Result.SUCCESS) == 0:
            c = 5

        categories[c-1].append(url)

    # Print the reproduction tables from "On Inferring TCP Behavior"
    print_table_2(categories)
    print_table_3(categories, icws)

if __name__ == "__main__":
    main()
