from scapy.all import send, sniff, sr, wrpcap  # send, receive, send/receive, and write pcap
from scapy.all import IP, TCP  # header constructors
from scapy.all import Padding  # packet layer


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

    def run_test(self, mss, pcap_output, rsport):
        """
        Performs the test on the specified URL.

        Args:
            mss: the maximum segment size in bytes
            pcap_output: pcap output filename
            rsport: receiver port (don't run multiple tests on the same port simultaneously)
        """
        syn_ack = self._send_syn(self.url, rsport, mss)

        if syn_ack:
            if syn_ack.sprintf("%TCP.flags%") == 'SA':
                responses, request = self._send_request(self.url, syn_ack)
                icw = self._get_icw(responses, mss)
                self._send_rst(request)

                wrpcap(pcap_output, responses)
                print("** ICW for ", self.url, ": ", icw)
        else:
            print("-> Could not get a SYN-ACK response")

    def _update_stream(self, packet):
        self.prev_seqno = self.cur_seqno
        self.cur_seqno = packet.seq

    def _stop_stream(self, packet):
        FIN = 0x01
        F = packet['TCP'].flags

        if packet['IP'].src != self.ip_of_url or packet.seq < self.prev_seqno or (
                F & FIN):
            # Response from a different source,
            # Retransmission or FIN packet
            return True
        else:
            return False

    # TODO: maybe try first the main page, then try this
    def _get_long_str(self):
        """
        Generates a very long arbitrary string with the intent to increase the URL length,
        so that the response is large too.
        """
        return 'chicken'*32

    def _send_syn(self, url, rsport, mss):
        # TODO: wrap this again
        # try:
        syn = IP(dst=url) / TCP(sport=rsport, dport=80, flags='S', seq=1,
                                options=[('MSS', mss)])
        # except:
        #     print("-> Could not create the SYN packet")
        #     return None

        ans, _ = sr(syn, timeout=self.ret_timeout)
        if ans:
            self.ip_of_url = ans[0][1].src
            #print("** ",url," replied from: ",self.ip_of_url)
            return ans[0][1]
        else:
            return None

    def _send_request(self, url, syn_ack):
        self.cur_seqno = 0
        self.prev_seqno = 0
        long_str = self._get_long_str()

        get_str = 'GET /' + long_str + ' HTTP/1.1\r\nHost: '
        get_str += url + '\r\nConnection: Close\r\n\r\n'
        get_rqst = IP(dst=syn_ack.src) \
                   / TCP(dport=80, sport=syn_ack.dport, seq=syn_ack.ack, ack=syn_ack.seq + 1,
                         flags='A') \
                   / get_str

        send(get_rqst)
        # prn function takes effect and acts on the packet every step of the way
        # stop_filter
        packets = sniff(filter='tcp src port 80', prn=self._update_stream,
                        timeout=self.ret_timeout, stop_filter=self._stop_stream)

        return packets, get_rqst

    def _send_rst(self, request):
        rst = IP(dst=request['IP'].dst) \
              / TCP(dport=80, sport=request.sport, seq=request.seq + len(request['TCP'].payload),
                    ack=self.prev_seqno + 1, flags='R')

        send(rst)

    def _get_icw(self, responses, mss):
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
                continue
            elif segment_size == 0 and not (flags & FIN):
                # Empty packet
                continue
            elif segment_size != mss or (flags & FIN):
                # Either not a full packet or a FIN packet
                # ICW test fails
                return 0
            else:
                if seen_seqno < pkt.seq:
                    seen_seqno = pkt.seq
                    icw += 1
        return icw

