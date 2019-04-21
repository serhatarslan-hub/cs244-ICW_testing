from scapy.all import send, sniff, sr, wrpcap  # send, receive, send/receive, and write pcap
from scapy.all import IP, TCP  # header constructors
from scapy.all import Padding  # packet layer
import socket  # for capturing bad host errors

class ICWTest(object):
    """
    Lightweight tool to perform an initial congestion window (ICW) test based on the TBIT test
    introduced by Padhye & Floyd 2001. Create one per URL.
    """

    def __init__(self, url, ret_timeout=10):
        """
        Args:
            url: the URL to perform the test on
            ret_timeout: retransmission timeout in seconds
        """
        self.url = url
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

        try:
            # SYN/ACK
            print("Opening connection...")
            syn_ack = self._open_connection(self.url, rsport, mss)

            # Validate ACK
            if not syn_ack.sprintf("%TCP.flags%") == 'SA':
                raise ICWTestException(Result.BAD_ACK)
            self.ip_of_url = syn_ack.src

            # Perform HTTP request and collect responses
            responses, request = self._send_request(self.url, syn_ack)
            print("Received %d responses" % len(responses))

            # Compute ICW
            icw = self._get_icw(responses, mss)

            # Close connection using a RST packet and write experiment output
            print("Closing connection...")
            self._close_connection(request)
            if pcap_output is not None:
                wrpcap(pcap_output, responses)

            return Result.SUCCESS, icw

        except ICWTestException as e:
            print("Test aborted: %s" % e.message)
            # Returns one of the Result options defined below
            return e.message, None

    def _open_connection(self, url, rsport, mss):
        """
        Sends a SYN and waits for the responding SYN/ACK to open the TCP connection.
        Returns the SYN/ACK response or raises a ICWTestException on error.
        """

        # Try to send SYN
        try:
            syn = IP(dst=url) \
                  / TCP(sport=rsport, dport=80, flags='S', seq=1, options=[('MSS', mss)])
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
              / TCP(dport=80, sport=request.sport, seq=request.seq + len(request['TCP'].payload),
                    ack=self.prev_seqno + 1, flags='R')

        send(rst)

    # TODO: maybe try first the main page, then try this
    def _get_long_str(self):
        """
        Generates a very long arbitrary string with the intent to increase the URL length,
        so that the response is large too.
        """
        return 'AAAAAaaaaaBBBBBbbbbbCCCCCcccccDDDDDdddddEEEEEeeeee'*27

    def _send_request(self, url, syn_ack):
        """
        Sends the HTTP request and waits for incoming packets with the provided filters.
        """
        self.cur_seqno = 0
        self.prev_seqno = 0
        long_str = self._get_long_str()

        # Construct GET requestr
        get_str = 'GET /' + long_str + ' HTTP/1.1\r\nHost: ' \
                  + url + '\r\nConnection: Close\r\n\r\n'
        get_rqst = IP(dst=syn_ack.src) \
                   / TCP(dport=80, sport=syn_ack.dport, seq=syn_ack.ack, ack=syn_ack.seq + 1,
                         flags='A') \
                   / get_str

        # Send request
        send(get_rqst)

        # Listen for responses. The prn function takes acts on every packet and stop_filter aborts
        # when we see a response from a different source, a retransmission, or a FIN packet.
        packets = sniff(filter='tcp src port 80', prn=self._update_stream,
                        timeout=self.ret_timeout, stop_filter=self._stop_stream)

        return packets, get_rqst

    def _update_stream(self, packet):
        """
        Update state helper for _send_request.
        """
        self.prev_seqno = self.cur_seqno
        self.cur_seqno = packet.seq

    def _stop_stream(self, packet):
        """
        Stop packet filter for _send_request.
        """
        FIN = 0x01
        F = packet['TCP'].flags

        if packet['IP'].src != self.ip_of_url or packet.seq < self.prev_seqno or (
                F & FIN):
            # TODO: any raise here?
            # Response from a different source,
            # Retransmission or FIN packet
            return True
        else:
            return False

    def _get_icw(self, responses, mss):
        """
        Computes the initial congestion window from the provided packet stream.
        """
        seen_seqno = 0
        icw = 0
        FIN = 0x01

        for pkt in responses:
            segment_size = len(pkt['TCP'].payload)
            pad = pkt.getlayer(Padding)
            flags = pkt['TCP'].flags

            if pad:
                segment_size -= len(pad)

            if pkt['IP'].src != self.ip_of_url:
                # Server responds from different source(s)
                raise ICWTestException(Result.DIFFERENT_SOURCE)
            elif segment_size == 0 and not (flags & FIN):
                # Empty packet
                continue
            elif segment_size != mss or (flags & FIN):
                # Either not a full packet or a FIN packet
                # ICW test fails
                raise ICWTestException(Result.FIN_PACKET)
            else:
                if seen_seqno < pkt.seq:
                    seen_seqno = pkt.seq
                    icw += 1
        return icw


class Result(object):
    MALFORMED_HOST = "malformed_host"  # User wrote bad host
    BAD_DNS = "dns"  # DNS lookup error (old host?)
    BAD_ACK = "bad_ack"
    SYN_ACK_TIMEOUT = "ack_timeout"
    FIN_PACKET = "fin"
    DIFFERENT_SOURCE = "different_source"
    SUCCESS = "success"


class ICWTestException(Exception):
    """
    We keep track of our own exceptions
    """
    pass