# Initial Congestion Window Size Measuring

This repository attempts to reproduce the results measuring the initial congestion window (ICW) size used by popular web servers. We aim to replicate the size measurements presented on "On Inferring TCP Behavior" by Jitendra Padhye and Sally Floyd.

The results are designed to be reproduced on a machine running Ubuntu 14.04. Below are the instructions to reproduce:

## Installation and Reproduction Steps:

1. Get a copy of the code

    ```
    git clone https://github.com/serhatarslan-hub/cs244-ICW_testing.git
    ```

2. Install the python dependencies and make sure they're accessible to the root user:
3. 
    ```
    cd cs244-ICW_testing
    sudo pip install -r requirements.txt
    ```

4. Reproduce the results (this will take some time):

    ```
    sudo python run_icw_test.py --url_list urls/URLList2001.txt
    ```

To estimate the initial congestion window of an IP or URL of your choice `YOUR_IP`, simply run:

```
sudo python run_icw_test.py --host YOUR_IP
```

For more options, see:

```
python run_icw_test.py --help
```

## Brief Description

[ to do: brief description of Padhye & Floyd method ]

The paper was published in 2001 which is when the Internet world was so much different that how it is today. With the paper, authors present their TCP Behavior Inference Tool (TBIT) which performs six different tests on publicly available web servers to understand their choice of behavior.  

We implement this method in python using scapy, a library for constructing, sending and receiving raw IP-layer packets. We rely on the common Linux tool `iptables` to set up firewall rules for our test. 

## Reproduction Philosophy

Our project re-runs only the initial congestion window size measurements of Padhye & Floyd. We aimed to base our reproduction as closely as possible on the written description in Padhye & Floyd. However, some small modifications were necessary to make this reproduction necessary.  

First of all, we did not use TBIT (the tool that authors used for their tests) during our reproduction. The main reason for this choice was related to the compatibility of the tool for our OS. The original TBIT (source code available on www.aciri.org/tbit/) was implemented for BSD operating system 19 years ago. Although a patch for Linux competibility was published in 2004, we could not make the tool work. Instead, we implemented our own initial congestion window size tester on Python 2.7 using Scapy packet manipulation module. Simplicity of usage and a great flexibility for packet by packet content manipulation were among the main reasons why we choose to work with Scapy. The complications that we encountered during our implementation are provided in later sections.  

Although we did not directly use authors' program, the testing methodology of our implementation follows the descriptions given on the paper step by step. Since the test itself is not a complicated procedure, we believe the instructions on the paper do not have an open point. All the categorization cases, and the test termination causes are implemented as desccribed on the paper with couple of exceptions presented in the following sections.  

During our preliminary tests, we realized that relatively large group of the web servers have adopted an ICW size of 10 or 16 MSS sized packets. As a result, we wanted to extend the table 3 presented on the paper and give explicit rows to some selected size of ICW sizes. Although we keep the `5 or more` row on the table, we believe showing ICW sizzes of 10 and 16 would help us to get the bigger picture in the Internet. The modified table is presented in the results section.

### Allowing a larger `MSS`  

While Padhye & Floyd's TBIT tool errored out whenever the server responded with a `MSS` bigger than advertised, we found this impractical for an `MSS` of 100 bytes as layed out in the paper. Many modern web servers will ignore requests for such a small `MSS` and when our tool is run in a commercial cloud environment such as Google Cloud, we found that networking infrastructure as well as virtualization platforms along the way often enforce a larger `MSS`. We thus don't penalize a server for returning data packets greater than our requested size and simply compute ICW as `total_payload_size / MSS`.  

Our way of measuring ICW is consistent with the unit definition of `cwnd` which is bytes. As long as the ICW is not filled up, the total amount of payload sent will be equal to `cwnd`. If there is a packet loss on the way the received payload size may be smaller than what is sent, but our implementation follows the sequence numbers of the received packets and terminates the test when a loss is detected. We also detect whether the response has finished before filling up the `cwnd` by catching any `FIN`, `RST` packets and/or retransmissions. In order to make sure `FIN` packets are sent at the end of responses, we use `Connection: Close` attribute in our `GET` requests.

### Finding large objects  

Padhye & Floyd request the main pages of the URLs during their ICW tests. Then they state the risk of not maxing out the ICW with the content of the main page. As a solution to this risk, we follow a method similar to that of Rüth et al. 2017 for ensuring that the response to our GET request maxes out `MSS*ICW` bytes. We simply make up a fairly large (more than 1460 bytes itself) request URL, i.e. `www.stanford.edu/AAAAAaaaaaBBBBBbbbbb...`. This almost always ensures either a `301 Moved Permanently` or a `404 Not Found` error. In both cases, the response typically contains the initial URL (and more), pushing us past the required window.  

Although the large URL trick doesn't ensure a large response, during our preliminary tests we realized that most of the websites had relatively small main page content. As a result, large URL trick would return relatively more tests with successful ICW estimation.  


## Results

[ to do ]

## Discussion

[ to do ]

## Complications and Limitations

- **Use of Scapy.** In using Scapy for our replication, we found that the tool can be slow at setting up sniffers, especially when running in virtualized environments. The default packet-receiving function `sniff()` requires us to use the slower `lfilter()` method for filtering packets in virtualized envirionments. With that setting, we consistently observed Scapy missing the first few packets before its sniffer was provisioned right after sending our GET request. We especially observed this case when we worked on a VM provisioned in an extremely high performance data center and queried URLs like www.google.com, likely only a few fiber hops away in the same datacenter (we tested this on Google Cloud). To circumvent this issue, we had to set up the sniffer asynchronously and ensure it was set up by the time we sent our first GET packet out. 

- **OS port blocking.** When using a tool like Scapy to send out raw L3 packets without sockets, the OS kernel closes any incoming connection with a RST packet before we even have a chance to process it. To avoid this, we had to set up a firewall rule before we start sending out any packets. We went with a blanket rule to avoid sending any RSTs on the source port:
 ```iptables -D OUTPUT -p tcp --sport %d --tcp-flags RST RST -j DROP```
where `%d` is our current evaluation port (unique for each URL and trial). After each test, we revert the firewall rule and close the connection by manually sending RST packet with Scapy. Please note that the provided firewall rules are for Linux operating system. Using other operating systems for running our implementation may still encounter the given port blocking problem.
