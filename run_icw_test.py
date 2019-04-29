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
    print("+------------+---------------+")
    print("|     Total |"+"{0: >15}".format(sum([len(c) for c in categories]))+ " |")
    print("+-----------+----------------+")


def print_table_3(categories, icws):
    """
    Only for category 1 URLs, compute and print results in Table 3 (Section 4.1)
    The values in icw[url] are guaranteed to be all the same at this point
    """
    icws = np.array([icws[url][0] for url in categories[0]])
    print("Table 3: ICW: Summary results")
    print("+------------+----------------+")
    print("| ICW size   | Servers        |")
    print("+------------+----------------+")
    print("|          1 |"+"{0: >15}".format(np.sum(icws == 1))+ " |")
    print("|          2 |"+"{0: >15}".format(np.sum(icws == 2))+ " |")
    print("|          3 |"+"{0: >15}".format(np.sum(icws == 3))+ " |")
    print("|          4 |"+"{0: >15}".format(np.sum(icws == 4))+ " |")
    print("|  5 or more |"+"{0: >15}".format(np.sum(icws >= 5))+ " |")
    print("|          8 |"+"{0: >15}".format(np.sum(icws == 8))+ " |")
    print("|         10 |"+"{0: >15}".format(np.sum(icws == 10))+ " |")
    print("|         16 |"+"{0: >15}".format(np.sum(icws == 16))+ " |")
    print("|         32 |"+"{0: >15}".format(np.sum(icws == 32))+ " |")
    print("+------------+----------------+")
    print("|      Total |"+"{0: >15}".format(len(icws))+ " |")
    print("+------------+----------------+")


def main():
    parser = ArgumentParser()
    parser.add_argument('--url_list', type=str,
                        help="File that contains the list of URLs to measure.")
    parser.add_argument('--host', type=str,
                        help="Host URL or IP address to run the test on")
    parser.add_argument('--mss', type=int, default=64,
                        help="MSS size (in bytes) to run the tests with")
    parser.add_argument('--main_page', action='store_true', default=False,
                        help="If specified, main page is requested from the URL.")
    parser.add_argument('--rqst_page', type=str, default=None,
                        help="Request for the specified page during HTTP GET.")
    parser.add_argument('--k', type=int, default=None,
                        help="Run over the url list in folds. Only execute fold k.")
    parser.add_argument('--kfolds', type=int, default=None,
                        help="Run over the url list in folds. Specify total folds.")
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

    if args.rqst_page is not None and args.main_page:
        print("Only one of --rqst_page and --main_page must be specified. (See -h for help.)")
        return
    if args.main_page:
        page2request = ''
    else:
        page2request = args.rqst_page

    if args.kfolds is not None and args.k is not None:
        partitions = np.array_split(urls, args.kfolds)
        urls = partitions[args.k]
    elif args.kfolds is not None or args.k is not None:
        print("--k and --kfolds must be used together. (See -h for help.)")
        return

    # In the original paper, "The MSS was set to 100 bytes."
    mss = args.mss
    # Number of trials per URL
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

    # Attempt to block port using iptables        
    os.system("iptables -A OUTPUT -p tcp --dport 80 --tcp-flags RST RST -j DROP" )
    try:
        for url, rsport in zip(urls, ports):
            print("="*32)

            # "We tested each server five times."
            for trial in range(num_trials):
                print("\n*** Trial %d ***" % (trial+1))
                print("Testing: %s on port %d" % (url, rsport))
                try:
                    experiment = ICWTest(url=url,page=page2request)
                    result, icw = experiment.run_test(
                        mss=mss, rsport=rsport, pcap_output=('debug.pcap' if args.debug else None))
                    if result == Result.SUCCESS:
                        print("==> Result: success!\n==> ICW Estimate: %d" % icw)
                    else:
                        print("==> Result: error: %s" % result)
                    results[url].append(result)
                    icws[url].append(icw)
                except Exception as e:
                    print("==> Internal error")
                    print(e)
                    results[url].append("internal_error")
                    icws[url].append(None)
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
