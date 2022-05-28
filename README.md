# Generating Labeled Training Datasets Towards Unified Network Intrusion Detection Systems

## Oveview
A script that creates supervised datasets from a publicly available security dataset.
The flow of datasets generation is as follows.

1. Prepare a PCAP dataset such as CICIDS 2018
2. Specify the PCAP and execute `TCPRewrite` or `TCPReplay`
3. Replay and get alerts from NIDS
4. Generate per-session labeled datasets with `mk_oss_data.py`
5. Generates per-packet labeled datasets with `mk_by_packet.py`
6. We publish the dataset of the result processed by us based on CICIDS 2018.

If you find this work useful, please cite our paper.
```
@article{Ishibashi2022,
  author = {Ryosuke Ishibashi and Kohei Miyamoto and Chansu Han and Tao Ban and Takeshi Takahashi and Jun{\textquotesingle}ichi Takeuchi},
  title = {Generating Labeled Training Datasets Towards Unified Network Intrusion Detection Systems},
  journal = {{IEEE} Access},
  year = {2022},
  publisher = {Institute of Electrical and Electronics Engineers ({IEEE})},
  volume = {10},
  pages = {53972--53986},
  doi = {10.1109/access.2022.3176098}
}
```

### 1. Prepare a PCAP dataset such as CICIDS 2018
Various datasets are open to the public for security research.
The types of datasets include PCAP data consisting of raw packet data and flow data consisting of statistical data generated based on packet data.
In this script, it is necessary to prepare a security data set consisting of PCAP.
Here we define the name of PCAP as `re_name`.

<br> 

### 2. Specify the PCAP and execute `TCPRewrite` and `TCPReplay`
Convert the prepared PCAP to a replayable format.
You need to translate the original PCAP internal IP address to the internal IP address on the network you are replaying.
`TCPRewrite` and `TCPReplay` do those things for you.
```
sudo tcprewrite --fragroute=${FRAGCONFPATH} --infile=${input.pcap} --outfile=${input.pcap}
```
Enter the packet size for fragmentation in `${FRAGCONFPATH}`.

<br> 

### 3. Replay and get alerts from NIDS
Replay the PCAP processed just before with `TCPReplay` and get an alert from the specified NIDS.
`TCPReplay` resends the specified PCAP on the specified interface
NIDS for which you want to get alerts must be installed on the specified network before replaying.
```
sudo tcpreplay -i ${interface} replay.pcap
```

<br> 

### 4. Generate per-session labeled datasets with `mk_oss_data.py`
Through the above process, I got a PCAP file and alerts for it.
However, it is not specified which packet group in PCAP each alert corresponds to.
`mk_oss_data.py` clarifies their correspondence and automatically associates alerts for each session during PCAP.
```
python mk_oss_data.py ${re_name} ${year}
```
`${year}` refers to the year of replay.

<br> 

### 5. Generates per-packet labeled datasets with `mk_by_packet.py`
Datasets for each packet is generated based on the data set for each session with `mk_by_packet.py`.
```
python mk_by_packet.py ${re_name}
```
When the script is executed, `binary` datasets with a binary label of normal or abnormal is generated for each packet, and `multi` datasets with the above types is generated for each packet.

<br> 

### 6. We publish the dataset of the result processed by us based on CICIDS 2018.
The data set generated in the above steps 1 to 5 based on CICIDS 2018 is released as a zip file. (`binary.zip` and `multi.zip`)

