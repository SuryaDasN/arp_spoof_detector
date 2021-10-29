#!/usr/bin/env python3

import scapy.all as scapy
import argparse

def get_argument():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", "--interface", dest="interface", help="Interface to detect ARP spoofing")
	options = parser.parse_args()
	if not options.interface:
		parser.error("[-] Please specify an interface, use --help for more info.")
	return options

def get_mac(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
	return answered_list[0][1].hwsrc


def sniff(interface):
	packet = scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
	if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
		try :
			real_mac = get_mac(packet[scapy.ARP].psrc)
			response_mac = packet[scapy.ARP].hwsrc

			if real_mac != response_mac:
				print("[*] You are under Attack!!!")

		except IndexError:
			pass


if __name__ == '__main__':

	print("[+] Checking ARP spoofing attack...")

	options = get_argument()
	sniff(options.interface)
