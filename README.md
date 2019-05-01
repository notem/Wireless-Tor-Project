# Website Fingerprinting against Wireless Tor

This repository contains all the code which we used during our analysis of website fingerprinting attacks against wireless Tor clients.
In this project, we have written a custom Tor crawler capable of collecting raw wireless (wlan) captures.
We used this crawler to capture a dataset of approximately 50k instances covering 100 different sites.
This dataset is then processed into plaintext representations (Tao Wang's format) using our data processing script.
Finally, we evaluated the threat of website fingerprinting against wireless traffic using three attacks from prior works.

We have divided this repository into several sub-directories covering code for different processes used in our project.
Each directory contains an additional readme which describes the purpose and usage of each script within the directory.

* `attacks/` - contains the scripts to perform the CUMUL [1], k-Fingerprinting [2], and Deep Fingerprinting [3] attacks

* `graphing/` - contains the scripts used to generate graphs used for displaying our results

* `processor/` - contains the data processing script

* `wireless-crawler/` - contains the wireless Tor website crawler software

In order to run any of the scripts in this repository, the python requirements must be installed.
* `pip3 install -r requirements.txt`

### Related Works

[1] Panchenko et al.  “Website fingerprinting at internet scale,” NDSS 2016.

[2] Hayes et al. “k-fingerprinting: A robust scalable website  fingerprinting  technique,” in USENIX 2016.

[3] Sirinam et al. “Deep fingerprinting: Undermining website fingerprinting defenses with deep  learning,” CCS 2018.

##### This capstone project was performed in coordination with the Center for Cybersecurity at RIT