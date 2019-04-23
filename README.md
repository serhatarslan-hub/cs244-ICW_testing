# Initial Congestion Window Size Measuring

This repository attempts to reproduce the results measuring the initial congestion window (ICW) size used by popular web servers. We aim to replicate the size measurements presented on "On Inferring TCP Behavior" by Jitendra Padhye and Sally Floyd.

The results are designed to be reproduced on a machine running Ubuntu 14.04. Below are the instructions to reproduce:

## Installation and Reproduction Steps:

1. Get a copy of the code

    ```
    git clone https://github.com/serhatarslan-hub/cs244-tbit_icw_reproduction.git
    ```

2. Install the python dependencies and make sure they're accessible to the root user:
3. 
    ```
    cd cs244-tbit_icw_reproduction
    sudo pip install -r requirements.txt
    ```

3. Reproduce the results (this will take some time):

    ```
    sudo python run_icw_test.py --url_list urls/URLListFeb2004.txt
    ```

To estimate the initial congestion window of an IP of your choice `YOUR_IP`, simply run:

```
sudo python run_icw_test.py --host YOUR_IP
```

For more options, see:

```
python run_icw_test.py --help
```

## Reproduction Philosophy

We aimed to base our reproduction as closely as possible on the written description in Padhye & Floyd.

However, some small modifications were necessary to make this reproduction necessary.

[ to do, expand ]

## Brief Description

[ to do: brief description of Padhye & Floyd method ]

We implement this method in python using scapy, a library for constructing, sending and receiving raw IP-layer packets. We rely on the common Linux tool `iptables` to set up firewall rules for our test. 

## Summary of Necessary Modifications

- **Finding large objects**. We follow a method similar to that of Rüth et al. 2017 for ensuring that the response to our GET request maxes out `mss*icw` bytes. We simply make up a ridiculously large request URL, i.e. `www.stanford.edu/chickenchickench...`. This almost always ensures either a `301 Moved Permanently` or a `404 Not Found` error. In both cases, the response typically contains the initial URL (and more), pushing us past the required window.
- **Allowing a larger `mss`.**  While Padhye & Floyd's TBIT tool errored out whenever the server responded with a `mss` bigger than advertised, we found this impractical for an `mss` of 100 bytes as layed out in the paper. Many webservers now will ignore requests for such a small `mss` and when our tool is run in a commercial cloud environment such as Google Cloud, we found that networking infrastructure along the way often enforces a larger `mss`. We thus don't penalize a server for returning data packets greater than our requested size and simply compute ICW as `total_bytes / mss`.

## Results

[ to do ]

## Discussion

[ to do ]

## Complications and Limitations

- **Use of Scapy.** In using scapy for our replication, we found that the tool can be slow at setting up sniffers, especially when running in virtualized environments. The default packet-receiving function `sniff()` requires us to use the slower `lfilter` method for filtering packets in virtualized envirionments. With that setting, we consistently observed scapy missing the first few packets before its sniffer was provisioned after sending our GET request, when we worked on a VM provisioned in an extremely high performance data centers and queried URLs like www.google.com, likely only a few fiber hops away in the same datacenter (we tested this on Google Cloud). To circumvent this issue, we had to set up the sniffer asynchronously and ensure it was set up by the time we sent our first GET packet out. 

- **OS port blocking.** When using a tool like scapy to send out raw L3 packets without sockets, the OS kernel will close any incoming connection with a RST packet before we even have a chance to process it. To avoid this, we had to set up a firewall rule. We went with a blanket rule to avoid sending any RSTs on the source port:
```iptables -D OUTPUT -p tcp --sport %d --tcp-flags RST RST -j DROP```
where `%d` is our current evaluation port (unique for each URL and trial).
