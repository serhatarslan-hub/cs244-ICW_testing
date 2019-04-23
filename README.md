# Initial Congestion Window Size Measuring

This repository attempts to reproduce the results measuring the initial congestion window (ICW) size used by popular web servers. We aim to replicate the size measurements presented on "On Inferring TCP Behavior" by Jitendra Padhye and Sally Floyd.

The results are designed to be reproduced on a machine running Ubuntu 14.04. Below are the instructions to reproduce:

## Installation and Reproduction Steps:

1. Get a copy of the code
    ```
    git clone https://github.com/serhatarslan-hub/cs244-tbit_icw_reproduction.git
    cd cs244-tbit_icw_reproduction
    ```

2. Install the python dependencies and make sure they're accessible to the root user:
    ```
    sudo pip install -r requirements.txt
    ```

3. Reproduce the results (this will take some time):
    ```
    sudo python run_icw_test.py
    ```

## Reproduction Philosophy


## Summary of Necessary Modifications


## Results


## Discussion


## Complications and Limitations