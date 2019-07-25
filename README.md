# network-capturer

### Requirements
- pyshark
- elasticsearch

### Usage
- subnet.config
  - Specify subnet range
  - ex. `SUBNET=192.168.0.0/16`
- from_pcap.py
  - Extract session info from pcap/pcapng file
  - `python3 from_pcap.py <input pcap file> <output json file>`
- send.py
  - Send session info to Elasticsearch
  - `python3 send.py <Elasticsearch URI> <Input json file>`