#!/usr/bin/python
from argparse import ArgumentParser
from icw_test import ICWTest
import random


def read_url_list(filename):
    with open(filename, "r") as f:
        return [line.split()[0] for line in f]


def main():
    parser = ArgumentParser()
    parser.add_argument('--url_list', type=str, required=True,
                        help="File that contains the list of URLs to measure.")
    args = parser.parse_args()

    url_list = read_url_list(args.url_list)
    print("Performing ICW test on %d URLs." % len(url_list))
    pcap_file = 'reproduction.pcap'

    # Some linux servers will automatically make it 64 per min, but 48 is safe
    mss = 48

    for url in url_list:
        print("*** %s" % url)
        # TODO: loop over ports insted
        # Start from 65k and go down
        rsport = random.randrange(2048, 65500)

        experiment = ICWTest(url=url)
        experiment.run_test(mss=mss, pcap_output='reproduction.pcap',
                            rsport=rsport)


if __name__ == "__main__":
    main()
