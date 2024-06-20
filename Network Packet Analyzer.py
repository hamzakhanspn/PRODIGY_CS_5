#-------------------------------------------------------------------------------
# Name:        Network Packet Analyzer
# Purpose:
#
# Author:      Hamza Khan
#
# Created:     02-06-2024
# Copyright:   (c) Hamza Khan 2024
# Licence:     <your licence>
#-------------------------------------------------------------------------------

#!/usr/bin/env python
import scappy.all as scapy
import argparse
from scapy.layers import http
def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets " )
    arguments = parser.parse_args()
    return arguments.interface

def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayar(http.HTTPRequest):
        print("[+] Http Request >> " + packet[http.HTTPRequest].host + packet[http.HTTPRequest].Path)
        if packet.haslayar(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = ["username", "password", "pass", "email"]
            for key in keys:
                if key in load:
                    print("[+] Possible password/username >> " + load)
                    break


iface = get_interface()
sniff(iface)
