#!/bin/env python3
import argparse
from scapy.all import *
from scapy.all import rdpcap
"""
When this is run, it will recursively search through directories to find
PCAP files. For each PCAP file, parse through grabbing timestamps and 
checking if packet is outgoing or incoming.
After PCAP is fully parsed, output to a text file (or otherwise specified)
Continue with the next PCAP until no other PCAP.
Should combine all the txt files into one directory
"""
# WLAN MAC address targets
TARGETS = [
           "00:25:22:50:8d:a7",  # Box1 USB wlan
           "9c:ef:d5:fc:32:67"   # Box2 USB wlan
          ]

# Frame types
MAN = 0  # management
CTR = 1  # control
DAT = 2  # data


def parse_pcap(file_name, adjust_times=True):
    "Parse PCAP file"
    a = rdpcap(file_name)
    start_time = None 
    sequence = []

    # check each packet in pcap sequentially
    for i in range(len(a)):
        pkt = a[i]  # current packet

        # only pay attention to WLAN packets
        if pkt.haslayer(Dot11) and pkt.type == DAT:

            direction = None

            # client is RA (reciever address)
            if pkt.addr1 in TARGETS:
                direction = -1
            # client is TA (transmitter address)
            elif pkt.addr2 in TARGETS:
                direction = 1

            #addr1 and addr2 are same as sometimes the Pi is the destination
            #thus to identify direction of packets, we need the following conditions
            if direction:

                # save initial start time
                if start_time is None:
                    start_time = pkt.time

                # get timestamp and packet length
                timestamp = pkt.time
                length = len(pkt)

                # add to sequence
                sequence.append((timestamp, direction*length))

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
    return parser.parse_args()


def preprocessor(inputhere, output):
    """Walk through the results directory, parse each result, write results
    to a text document"""
    next_site_num = 0
    site_to_num = dict()
    num_to_inst = dict()
    a = 0
    # loop over all files in directory structure
    for root, dirs, files in os.walk(inputhere):
        # filter for only pcap files
        files = [fi for fi in files if fi.endswith(".pcap")]

        # parse each capture and save results
        for fi in files:
            # print out current file num
            a += 1
            print("{}          ".format(a,len(files)), end="\r")
            
            folder = root.split(os.path.sep)[-1]
            if len(folder.split("_")) == 3:
                batch, site, instance = folder.split("_")
                path = os.path.join(root, fi)
                try:
                    sequence = parse_pcap(path)
                    if len(sequence) > 50:
                        if site not in site_to_num:
                            site_to_num[site] = next_site_num
                            num_to_inst[site] = 0
                            next_site_num += 1
                        fname = str(site_to_num[site]) + "_" + str(num_to_inst[site])
                        path = os.path.join(output, fname)
                        save_to_file(sequence, path)  # Write actual write file
                        num_to_inst[site] += 1
                except:
                    print("Error while parsing pcap!")


if __name__ == '__main__':
    args = parse_arguments()
    preprocessor(args.INPUT, args.OUTPUT)
