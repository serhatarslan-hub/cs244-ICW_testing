from scapy.all import send, sniff, sr, wrpcap  # send, receive, send/receive, and write pcap
from scapy.all import IP, TCP  # header constructors
from scapy.all import Padding  # packet layer
import socket  # for capturing bad host errors
import os
from multiprocessing.pool import ThreadPool

FIN = 0x01
RST = 0x04

class ICWTest(object):
    """
    Lightweight tool to perform an initial congestion window (ICW) test based on the TBIT test
    introduced by Padhye & Floyd 2001. Create one per URL.
    """

    def __init__(self, url, page=None, ret_timeout=4):
        """
        Args:
            url: the URL to perform the test on
            ret_timeout: retransmission timeout in seconds
        """
        self.url = url
        self.page2request = page
        self.ret_timeout = ret_timeout
        self.cur_seqno = 0
        self.prev_seqno = 0
        self.ip_of_url = None

    def run_test(self, mss, rsport, pcap_output=None):
        """
        Performs the test on the specified URL.

        Args:
            mss: the maximum segment size in bytes
            rsport: receiver port (don't run multiple tests on the same port simultaneously)
            pcap_output: pcap output filename to write trace (if provided)

        Returns tuple (result, icw), where icw will be None unless result is Result.SUCCESS.
        """
        self.mss = mss
        self.rsport = rsport

        try:
            # SYN/ACK
            print("Opening connection...")
            syn_ack = self._open_connection(self.url, rsport)

            # Validate ACK
            if not syn_ack.sprintf("%TCP.flags%") == 'SA':
                raise ICWTestException(Result.BAD_ACK)
            self.ip_of_url = syn_ack.src

            # Perform HTTP request and collect responses
            responses = self._send_request(self.url, syn_ack)
            print("Received %d responses" % len(responses))
            if len(responses) == 0:
                raise ICWTestException(Result.HTTP_TIMEOUT)

            # Compute ICW
            icw = self._get_icw(responses)

            # Write experiment output
            if pcap_output is not None:
                wrpcap(pcap_output, responses)

            if icw == 0:
                raise ICWTestException(Result.HTTP_TIMEOUT)

            return Result.SUCCESS, icw

        except ICWTestException as e:
            print("Test aborted: %s" % e.message)
            # Returns one of the Result options defined below
            return e.message, None

        finally:
            # Close connection using a RST packet
            if hasattr(self, "request"):
                self._close_connection(self.request)

    def _open_connection(self, url, rsport):
        """
        Sends a SYN and waits for the responding SYN/ACK to open the TCP connection.
        Returns the SYN/ACK response or raises a ICWTestException on error.
        """

        # Try to send SYN
        try:
            syn = IP(dst=url) \
                  / TCP(sport=rsport, dport=80, flags='S', seq=1,
                        options=[('MSS', self.mss)])
        except socket.herror:
            raise ICWTestException(Result.MALFORMED_HOST)
        except socket.gaierror:
            raise ICWTestException(Result.BAD_DNS)

        # Wait for ack
        ans, _ = sr(syn, timeout=self.ret_timeout, retry=2)
        if not ans:
            # TODO: verify that that is what happened here
            raise ICWTestException(Result.SYN_ACK_TIMEOUT)
        
        return ans[0][1]

    def _close_connection(self, request):
        """
        Sends a packet with the RST flag set to close the TCP connection.
        """
        rst = IP(dst=request['IP'].dst) \
              / TCP(dport=80, sport=request.sport,
                    seq=request.seq + len(request['TCP'].payload),
                    ack=self.prev_seqno + 1, flags='R')

        send(rst)

    def _get_page2request(self):
        """
        Generates a very long arbitrary string with the intent to increase the
        URL length, so that the "URL not found" response is large too.
        """
        if self.page2request is not None:
            return self.page2request
        else:
            return 'AAAAAaaaaaBBBBBbbbbbChCCCcicccDDcDDddkddEEEEEeeene'*27

    def _start_sniff(self):
        # Listen for responses. The prn function takes acts on every packet and
        # stop_filter aborts when we see a response from a different source,
        # a retransmission, or a FIN or RST packet.
        f = lambda pck: 'TCP' in pck and pck['TCP'].dport == self.rsport
        packets = sniff(lfilter=f,
                        timeout=self.ret_timeout,
                        stop_filter=self._stop_stream)
        return packets

    def _send_request(self, url, syn_ack):
        """
        Sends the HTTP request and waits for incoming packets with the provided
        filters.
        """
        self.cur_seqno = 0
        self.prev_seqno = 0
        path2page = self._get_page2request()

        # Construct GET request
        get_str = 'GET /' + path2page + ' HTTP/1.1\r\nHost: ' \
                  + url + '\r\nConnection: Close\r\n\r\n'
        self.request = IP(dst=syn_ack.src) \
                       / TCP(dport=80, sport=syn_ack.dport, seq=syn_ack.ack,
                             ack=syn_ack.seq + 1, flags='A') \
                       / get_str

        # Start listener
        # We do this on a background thread to ensure that sniff is set up by
        # the time that we are ready to receive packets.
        # Otherwise this fails for VMs with extremely fast attachments testing
        # closeby servers. (e.g. attempting to run this test for google.com
        # from a server provisioned on Google Cloud).
        pool = ThreadPool(processes=1)
        async = pool.apply_async(self._start_sniff)

        # Send request
        send(self.request)
        packets = async.get()
        pool.close()
        pool.join()

        return packets


    def _stop_stream(self, packet):
        """
        Stop packet filter for _send_request.
        """
        flags = packet['TCP'].flags
        segment_size = len(packet['TCP'].payload)
        pad = packet.getlayer(Padding)
        if pad:
            segment_size -= len(pad)
        

        if packet.seq <= self.prev_seqno and packet.seq != self.cur_seqno:
            return True

        elif packet.seq != self.cur_seqno and self.cur_seqno is not 0:
            print("Received out of order packet! %d, expected %d"
                  % (packet.seq, self.cur_seqno))
            raise ICWTestException(Result.PACKET_LOSS)
            return True

        elif flags & FIN or flags & RST:
            raise ICWTestException(Result.FIN_RST_PACKET)
            return True
        
        # We decide to allow these cases
        # elif segment_size > self.mss:
        #     raise ICWTestException(Result.LARGE_MSS)
        #     return True
        # elif packet['IP'].src != self.ip_of_url:
        #     raise ICWTestException(Result.DIFFERENT_SOURCE)
        #     return True

        elif segment_size < self.mss \
            and segment_size != 0:
            raise ICWTestException(Result.FILE_ENDED)
            return True

        else:
            # Update state
            self.cur_seqno = packet.seq + segment_size
            self.prev_seqno = packet.seq
            return False

    def _get_icw(self, responses):
        """
        Computes the initial congestion window from the provided packet stream.
        """
        seen_seqno = -1
        total_bytes = 0

        for packet in responses:
            segment_size = len(packet['TCP'].payload)
            pad = packet.getlayer(Padding)
            if pad:
                segment_size -= len(pad)

            if seen_seqno <= packet.seq:
                seen_seqno = packet.seq
                total_bytes += segment_size

        return total_bytes // self.mss


class Result(object):
    # Success result
    SUCCESS = "success"

    # (1) "TBIT did not receive a SYN/ACK in response to its SYN,
    #      even after retransmissions, so no connection was established"
    #     (we interpret this as retry=2)
    SYN_ACK_TIMEOUT = "ack_timeout"

    # (2)  "The server sent a SYN/ACK but did not send any data in
    #       response to the HTTP request"
    HTTP_TIMEOUT = "http_timeout"

    # (3) "TBIT detected a packet loss"
    PACKET_LOSS = "packet_loss"

    # (4) "The remote server sent a packet with the RST or FIN flag set,
    #      before the test was complete"
    FIN_RST_PACKET = "fin_or_rst"

    # (5) "The remote server sent a packet with MSS larger than the one
    #      TBIT had specified"
    LARGE_MSS = "large_mss"

    # Additional failure modes not explicitly mentioned in the paper:
    MALFORMED_HOST = "malformed_host"  # User wrote bad host
    BAD_DNS = "dns"  # DNS lookup error (old host?)
    BAD_ACK = "bad_ack"  # Bad ack response
    DIFFERENT_SOURCE = "different_source"  # Different IP response
    FILE_ENDED = "file_ended"  # Got a smaller than expected packet, so can't fill the ICW

    # All possible results
    ALL_RESULTS =  [SUCCESS, MALFORMED_HOST, BAD_DNS, BAD_ACK, DIFFERENT_SOURCE, SYN_ACK_TIMEOUT,
                    HTTP_TIMEOUT, PACKET_LOSS, FIN_RST_PACKET, LARGE_MSS]


class ICWTestException(Exception):
    """
    We keep track of our own exceptions
    """
    pass