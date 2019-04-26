# Initial Congestion Window Size Measuring

This repository attempts to reproduce the results of measuring the initial congestion window (ICW) size used by popular web servers. We aim to replicate the size measurements presented on "On Inferring TCP Behavior" by Jitendra Padhye and Sally Floyd.

The results are designed to be reproduced on a machine running Ubuntu 14.04. However other platforms (i.e. Windows, macOS) may run the tester. For reproducing results in such platforms, please make sure the operating system or the hypervisor (if running on a vm) does not change or interrupt the packet communication generated by our tester. (This may require configuration change on local firewall rules or hypervisor settings. Please see our report below for the issues we encountered.) Instructions to reproduce the results are as the following:

## Installation and Reproduction Steps:

1. Get a copy of the code

    ```
    git clone https://github.com/serhatarslan-hub/cs244-ICW_testing.git
    ```

2. Install the python dependencies and make sure they're accessible to the root user:
 
    ```
    cd cs244-ICW_testing
    sudo pip install -r requirements.txt
    ```

3. Reproduce the results with a modern list of URLS* (this will take some time):

    ```
    sudo python run_icw_test.py --mss 100 --url_list urls/QuantasPopularURLs.txt
    ```  
    *Please note that we are using the list of most popular 20 thousand URLS provided by  https://www.quantcast.com/top-sites/.

To estimate the initial congestion window of an IP or URL of your choice `YOUR_IP` and a specific page of your choice `PATH_TO_PAGE`, simply run:

```
sudo python run_icw_test.py --host YOUR_IP --rqst_page PATH_TO_PAGE
```

To perform the tests in a more realistic environment, set `--mss` value to 1460. (Please note that 1460 bytes for MSS will be likely to fail the ICW tests that reproduces the suggested mechanism by [Padhye, Floyd 01])  
  
Our tests request for a non-existing very long page from every URL. This is implemented to make sure response content is long enough to fill the ICW as suggested by [Rüth, Bormann, Hohlfeld 17]. To request for the main page of the URL, simply pass `--main_page` argument while running the tester.  

```
sudo python run_icw_test.py --mss 100 --url_list urls/QuantasPopularURLs.txt --main_page
```  

For more options, see:

```
python run_icw_test.py --help
```

## Brief Description  

The paper [Padhye, Floyd 01]  was published in 2001 - when the Internet world was so much different that how it is today - in order to provide a survey that presents the general behavior of TCP implementations throughout the Internet. Since TCP had many user-configurable parameters, fairness and stability concerns were tried to be addressed via the obtained "diverity vs. standardization" results. Such results could help us understand the current big picture of the Internet which then could be interpreted when designing simulations or even new systems. The results would also show how much is Internet community in obedience with the proposed standards (RFCs). 

With the paper, authors present their TCP Behavior Inference Tool (TBIT) which performs six different tests on publicly available web servers to understand their choice of behavior. Those tests can be listed as initial value of congestion window (ICW), congestion control algorithm (CCA), conformant congestion control (CCC), selective acknowledgements (SACK), time wait duration, and response to ECN. Our reproduction focuses solely on the ICW tests which aim to estimate the initial congestion window size of web servers throughout the Internet.  

Congestion window size is one of the two metrics to decide how much data can be sent before any acknowledgement of arrival is received. Many congestion control algorithms start from a relatively small value of congestion window size and slowly increase until congestion is perceived. However, the ICW determines how much data to be sent without any feedback on current congestion on the network. As a consequence, ICW size selection brings a trade-off between under-utilizing the available capacity vs. putting too much stress on the network.  

In 2002, RFC 3390 (Increasing TCP's Initial Window) set a standard for determining ICW for implementors of TCP congestion control. The ICW function would simply be `min (4*MSS, max (2*MSS, 4380 bytes))` where `MSS` is the maximum segment size (in bytes) which set by the negotiation of the two end-hosts during the TCP handshake. Our evaluation of this function and its effect on the results of our ICW tests are analyzed in discussion section of our report.  

The way [Padhye, Floyd 01] perform their tests includes a simple TCP handshake and a HTTP GET request. After the request, no acknowledgements are sent for arriving packets which results in timeouts on the sender side after ICW amount of data is sent, so that the sender retransmits the previosly sent packets. The tester then interprets this retransmission as "everything sent before was inside the filled ICW". In order to be able to infer about ICW size, one needs to make sure that the file being sent is larger than ICW. Since finding a very large file on every web server they test was not feasible, [Padhye, Floyd 01] tried to solve this by keeping the MSS very small during their tests which would eventually decrease the ICW size. Quality of tests with the choice of small MSS is evaluated in the discussion section of our report.  

## Reproduction Philosophy

Our project re-runs only the initial congestion window size measurements of Padhye & Floyd. We aimed to base our reproduction as closely as possible on the written description in Padhye & Floyd. However, some small modifications were necessary to make this reproduction necessary.  

First of all, we did not use TBIT (the tool that authors used for their tests) during our reproduction. The main reason for this choice was related to the compatibility of the tool for our OS. The original TBIT (source code available on www.aciri.org/tbit/) was implemented for BSD operating system 19 years ago. Although a patch for Linux competibility was published in 2004, we could not make the tool work. Instead, we implemented our own initial congestion window size tester on Python 2.7 using Scapy packet manipulation module. Simplicity of usage and a great flexibility for packet by packet content manipulation were among the main reasons why we choose to work with Scapy. The complications that we encountered during our implementation are provided in later sections.  

During our preliminary tests, we realized that relatively large group of the web servers have adopted an ICW size of 10 or 16 MSS sized packets (when MSS is small enough). As a result, we wanted to extend the table 3 presented on the paper and give explicit rows to some selected size of ICW configurations. Although we keep the `5 or more` row on the table, we believe showing ICW sizes of 10 and 16 would help us to get the bigger picture in the Internet. The modified table is presented in the results section.  

Although we did not directly use authors' program, the testing methodology of our implementation follows the descriptions given on the paper step by step. Since the test itself is not a complicated procedure, we believe the instructions on the paper do not have an open point. All the categorization cases, and the test termination causes are implemented as desccribed on the paper with couple of exceptions presented in the following sub-sections.  

### Allowing a larger `MSS`  

While Padhye & Floyd's TBIT tool errored out whenever the server responded with a `MSS` bigger than advertised, we found this impractical for an `MSS` of 100 bytes as layed out in the paper. Many modern web servers will ignore requests for such a small `MSS` and when our tool is run in a commercial cloud environment such as Google Cloud, we found that networking infrastructure as well as virtualization platforms along the way often enforce a larger `MSS`. We thus don't penalize a server for returning data packets greater than our requested size and simply compute ICW as `total_payload_size / MSS`.  

Our way of measuring ICW is consistent with the unit definition of `cwnd` which is bytes. As long as the ICW is filled up, the total amount of payload sent will be equal to `cwnd`. If there is a packet loss on the way, the received payload size may be smaller than what is sent, but our implementation follows the sequence numbers of the received packets and terminates the test when a loss is detected. We also detect whether the response has finished before filling up the `cwnd` by catching any `FIN`, `RST` packets and/or retransmissions. In order to make sure `FIN` packets are sent at the end of responses, we use `Connection: Close` attribute in our `GET` requests.  

### Finding large objects  

Padhye & Floyd request the main pages of the URLs during their ICW tests. Then they state the risk of not maxing out the ICW with the content of the main page. As a solution to this risk, we follow a method similar to that of Rüth et al. 2017 for ensuring that the response to our GET request maxes out `MSS*ICW` bytes. We simply make up a fairly large (more than 1460 bytes itself) request URL, i.e. `www.stanford.edu/AAAAAaaaaaBBBBBbbbbb...`. This almost always ensures either a `301 Moved Permanently` or a `404 Not Found` error. In both cases, the response typically contains the initial URL (and more), pushing us past the required window.  

Although the large URL trick doesn't ensure a large response, during our preliminary tests we realized that most of the websites had relatively small main page content. As a result, large URL trick would return relatively more tests with successful ICW estimation. Nevertheless, one can re-run the tests with proper arguments as provided in the reproduction instructions to request for the main page of the URL.   

## Results

[ to do ]

## Discussion

[ to do ]

## Complications and Limitations

- **Use of Scapy.** In using Scapy for our replication, we found that the tool can be slow at setting up sniffers, especially when running in virtualized environments. The default packet-receiving function `sniff()` requires us to use the slower `lfilter()` method for filtering packets in virtualized envirionments. With that setting, we consistently observed Scapy missing the first few packets before its sniffer was provisioned right after sending our GET request. We especially observed this case when we worked on a VM provisioned in an extremely high performance data center and queried URLs like www.google.com, likely only a few fiber hops away in the same datacenter (we tested this on Google Cloud). To circumvent this issue, we had to set up the sniffer asynchronously and ensure it was set up by the time we sent our first GET packet out. 

- **OS port blocking.** When using a tool like Scapy to send out raw L3 packets without sockets, the OS kernel closes any incoming connection with a RST packet before we even have a chance to process it. To avoid this, we had to set up a firewall rule before we start sending out any packets. We went with a blanket rule to avoid sending any RSTs on the source port:
 ```iptables -D OUTPUT -p tcp --sport %d --tcp-flags RST RST -j DROP```
where `%d` is our current evaluation port (unique for each URL and trial). After each test, we revert the firewall rule and close the connection by manually sending RST packet with Scapy. Please note that the provided firewall rules are for Linux operating system. Using other operating systems for running our implementation may still encounter the given port blocking problem.  

- **Default Hypervisor Configurations** During our experiments, we have realized that our hypervisor (Oracle VM Virtualbox) changed the MSS option in the outgoing packets to 1460 bytes even when we manually set it to different values. This was mainly because of the default behavior of the hypervisor itself as reported in https://www.virtualbox.org/ticket/15256 bug report. Since this issue would prevent obtaining the desired behavior from the web servers, the following steps may be helpful to overcome the problem (if encountered):  

    1. Use the bridged networking option for Virtualbox. (Go to Machine > Settings > Network > Adapter 1 and set it to "Bridged")  

    2. Set DHCP for the connected interface statically and steal the IP information of the host interface to connect the VM interface to the Internet. Namely, edit /etc/network/interfaces on the VM.  

    ```
    iface eth1 inet static  
    	address [host ip]  
            gateway [host gateway]  
            broadcast [host broadcast]  
            dns-nameservers 8.8.8.8
    ```  

    You may need to run `sudo ifdown eth1` and `sudo ifup eth1` after this or reboot the VM.
