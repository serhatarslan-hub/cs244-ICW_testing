#!/usr/bin/python
import numpy as np
import os
from argparse import ArgumentParser
from icw_test import ICWTest, Result
from collections import defaultdict


def read_url_list(filename):
    # TODO: read IPs
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

    # "The MSS was set to 100 bytes."
    mss = 100

    # Loop over ports from 2048 to 65500 in a random order
    ports = np.random.permutation(np.arange(2048, 65500))

    # Results becomes a map from URL to 5 trials like
    # {"www.google.com": ["success", "success", "success", "success", "fin"],
    #  "www.apple.com": ["fin", "fin", "fin", "fin", "fin"]
    #  ...}
    # icws becomes a map to 
    results = defaultdict(list)
    icws = defaultdict(list)

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
            # "We tested each server five times."
            for trial in range(5):
                print("*** Trial %d ***" % (trial+1))
                experiment = ICWTest(url=url)
                result, icw = experiment.run_test(
                    mss=mss, rsport=rsport, pcap_output='debug.pcap')
                if result == Result.SUCCESS:
                    print("==> Result: success!\n==> ICW Estimate: %d" % icw)
                else:
                    print("==> Result: error: %s" % result)
                results[url].append(result)
                icws[url].append(icw)
        finally:
            # Undo firewall rule
            os.system("iptables -t raw -D PREROUTING -p tcp --dport %d -j DROP"
                      % rsport)
    
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

    print("Table 2: ICW: Server categories")
    print("+----------------------------+")
    print("| Category  | Servers        |")
    print("+----------------------------+")
    for i, c in enumerate(categories):
        print(("|         %d |" % (i+1))+"{0: >15}".format(len(c))+ " |")
    print("|     Total |"+"{0: >15}".format(sum([len(c) for c in categories]))+ " |")
    print("+----------------------------+")

    # Only for category 1 URLs, compute results in Table 3 (Section 4.1)
    # The values in icw[url] are guaranteed to be all the same at this point
    icws = np.array([icws[url][0] for url in categories[0]])
    print("Table 3: ICW: Summary results")
    print("+----------------------------+")
    print("| ICW size  | Servers        |")
    print("+----------------------------+")
    print("|         1 |"+"{0: >15}".format(np.sum(icws == 1))+ " |")
    print("|         2 |"+"{0: >15}".format(np.sum(icws == 2))+ " |")
    print("|         3 |"+"{0: >15}".format(np.sum(icws == 3))+ " |")
    print("|         4 |"+"{0: >15}".format(np.sum(icws == 4))+ " |")
    print("| 5 or more |"+"{0: >15}".format(np.sum(icws >= 5))+ " |")
    print("|     Total |"+"{0: >15}".format(len(icws))+ " |")
    print("+----------------------------+")

if __name__ == "__main__":
    main()
