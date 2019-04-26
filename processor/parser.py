#!/bin/env python3
import argparse
import os
import sys
from scapy.all import *
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP
from multiprocessing import Pool
import json

"""
When this is run, it will recursively search through directories to find
PCAP files. For each PCAP file, parse through grabbing timestamps and 
checking if packet is outgoing or incoming.
After PCAP is fully parsed, output to a text file (or otherwise specified)
Continue with the next PCAP until no other PCAP.
Should combine all the txt files into one directory
"""
# WLAN MAC address and IP targets
# if your captures are polluted 
#   (ie. captures contain traffic from multiple crawler instances) 
#   then the resulting traces will be bad!
TARGETS = [
    "00:25:22:50:8d:a7",  # Box1 USB wlan
    "9c:ef:d5:fc:32:67",  # Box2 USB wlan
    "192.168.1.176",
    "192.168.1.198"
]

# TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

# Wireless Frame types
MAN = 0  # management
CTR = 1  # control
DAT = 2  # data


def parse_pcap(path, adjust_times=True, client_ip=None):
    """
    function processes IP-level capture pcap into a sequence of 2-tuple packet representations.
    the Scapy library is used for parsing the captures
    """
    sequence = []
    packets = rdpcap(path)
    start_time = None
    for packet in packets:
        if IP in packet:

            direction = None
            if client_ip:
                if packet[IP].dst == client_ip:
                    direction = -1
                elif packet[IP].src == client_ip:
                    direction = 1
            else:
                if packet[IP].dst in TARGETS:
                    direction = -1
                elif packet[IP].src in TARGETS:
                    direction = 1

            if not direction:
                continue

            timestamp = packet.time
            # save initial start time
            if start_time is None:
                start_time = timestamp
            length = len(packet)

            # add to sequence
            sequence.append((timestamp, direction * length))

    # adjust packet times such that the first packet is at time 0
    if adjust_times and start_time:
        sequence = [(pkt[0] - start_time, pkt[1]) for pkt in sequence]

    return sequence


def parse_pcap_raw(file_name, adjust_times=True, target=None):
    """
    function processes wireless capture pcap into a sequence of 2-tuple packet representations.
    the Scapy library is used for parsing the captures
    """
    a = rdpcap(file_name)
    start_time = None
    sequence = []

    # check each packet in pcap sequentially
    for i in range(len(a)):
        pkt = a[i]  # current packet

        # only pay attention to WLAN packets
        # pkt.haslayer(Dot11) should also handle Dot11FCS occurrences,
        #   however some scapy versions reportedly have issues
        if (pkt.haslayer(Dot11) or pkt.haslayer(Dot11FCS)) and pkt.type == DAT:

            direction = None
            if target:
                if pkt.addr1 == target:
                    direction = -1
                elif pkt.addr2 == target:
                    direction = 1
            else:
                # client is RA (reciever address)
                if pkt.addr1 in TARGETS:
                    direction = -1
                # client is TA (transmitter address)
                elif pkt.addr2 in TARGETS:
                    direction = 1

            # addr1 and addr2 are same as sometimes the Pi is the destination
            # thus to identify direction of packets, we need the following conditions
            if direction:

                # save initial start time
                if start_time is None:
                    start_time = pkt.time

                # get timestamp and packet length
                timestamp = pkt.time
                length = len(pkt)

                # add to sequence
                sequence.append((timestamp, direction * length))

    # adjust packet times such that the first packet is at time 0
    if adjust_times and start_time:
        sequence = [(pkt[0] - start_time, pkt[1]) for pkt in sequence]

    return sequence


def save_to_file(sequence, path, delimiter='\t'):
    """save a cell sequence (2-tuple of time and direction) to a file"""
    if not os.path.exists(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))
    with open(path, 'w') as file:
        for packet in sequence:
            line = '{t}{b}{d}\n'.format(t=packet[0], b=delimiter, d=packet[1])
            file.write(line)


def parse_arguments():
    """parse command-line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--INPUT",
                        required=True)
    parser.add_argument("--OUTPUT",
                        required=True)
    parser.add_argument("--TYPE",
                        required=True,
                        default="default",
                        choices=["raw", "default"])
    parser.add_argument("--SITES",
                        required=False,
                        default="./sites")
    return parser.parse_args()


def in_network_task(filepath):
    """function to handle the processing of a single pcap file, for IP-level captures"""
    root, fi = filepath
    folder = root.split(os.path.sep)[-1]
    if len(folder.split("_")) == 3:
        batch, site, instance = folder.split("_")
        path = os.path.join(root, fi)
        try:
            sequence = parse_pcap(path)
            return (site, sequence)
        except Exception as exc:
            print("encountered exception", exc)


def out_network_task(filepath):
    """function to handle the processing of a single pcap file, for wireless captures"""
    root, fi = filepath
    folder = root.split(os.path.sep)[-1]
    if len(folder.split("_")) == 3:
        batch, site, instance = folder.split("_")
        path = os.path.join(root, fi)
        try:
            sequence = parse_pcap_raw(path)
            return (site, sequence)
        except Exception as exc:
            print("encountered exception", exc)
            return (site, None)


def preprocessor(inputhere, output, site_map, raw=False):
    """
    Start a multiprocessing pool to handle processing pcap files in parallel.
    Packet sequences are saved to a text file following Wang's format as the worker processes produce results.
    The site names are mapped to numbers dynamically, and these mappings are saved for later reference.
    This function will load prior mappings if a file is provided.
    :param inputhere: root directory path containing pcap files
    :param output: directory which to save trace files
    :param site_map: path to file where site to number mappings should be saved
    :return: nothing
    """

    # map site name to a number
    # track number of instances for each site number
    num_to_inst = dict()  # keys == site_name
    site_to_num = dict()  # keys == site_number
    next_site_num = 0

    # load site_map from file if it exists
    # site_map is used to map site names to numbers
    # instance counters are not saved between runs
    if os.path.exists(site_map):
        with open(args.site_map, "r") as fi:
            site_to_num = json.load(fi)
        if len(site_to_num.values()) > 0:
            next_site_num = max(site_to_num.values()) + 1
        else:
            next_site_num = 0

    # create list of pcap files to process
    flist = []
    for root, dirs, files in os.walk(inputhere):
        # filter for only pcap files
        files = [fi for fi in files if fi.endswith(".pcap")]
        flist.extend([(root, f) for f in files])

    # process pcaps in parallel
    with Pool() as pool:
        if raw:
            iter = pool.imap_unordered(out_network_task, flist)
        else:
            iter = pool.imap_unordered(in_network_task, flist)

        # iterate through processed pcaps as they become available
        # pcaps are parsed in parallel, however parsed sequences are saved to file in serial
        for i, res in enumerate(iter):
            print("Progress: {}/{}                \r".format(i + 1, len(flist)), end="")

            # if results of task are bad, ignore
            if res is None or len(res) != 2:
                continue

            # save the sequence to file
            site, sequence = res[0], res[1]
            if sequence is not None:
                # add site to mappings if first occurrence
                if site not in site_to_num.keys():
                    site_to_num[site] = next_site_num
                    num_to_inst[next_site_num] = 0
                    next_site_num += 1

                # save to file
                out_path = os.path.join(output, "{}-{}".format(site_to_num[site],
                                                               num_to_inst[site_to_num[site]]))
                save_to_file(sequence, out_path)

                # increase the site number by one
                num_to_inst[site_to_num[site]] += 1

    # lazy make directories
    try:
        os.makedirs(os.path.dirname(site_map))
    except:
        pass

    # delete old site_map
    if os.path.exists(site_map):
        os.remove(site_map)

    # save site_map to json
    with open(site_map, "w") as fi:
        json.dump(site_map, fi, indent=4)


if __name__ == '__main__':
    args = parse_arguments()
    preprocessor(args.INPUT, args.OUTPUT, args.SITES, raw=args.TYPE == "raw")
