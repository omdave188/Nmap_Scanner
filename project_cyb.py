#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print("welcome to nmap scanner!!")

ip_addr = input("Please enter an ip address you want to scan:")

print("You have entered this ip:", ip_addr)

type(ip_addr)

resp = input(***\nPlease enter the type of scan you want to run :
		1) SYN-ACK Scan
		2) UDP Scan
		3) Comprehensive Scan \n***)

print("You have selected the option:",resp)

resp_disct = {'1':['-v -sS', 'tcp'],'2':['-v -sU','udp'],'3':[-v -sS -sV -sC -A -O','tcp']}

if resp not in resp_dict.keys():
	print("Enter a valid option")
else:
	print("nmap version:"scanner.nmap_version())
	scanner.scan(ip_addr,"1-10000",resp_dict[resp][0])
	print(scanner.scaninfo())
	if scanner.scaninfo()=='up':
		print("Scannerstatus :",scanner[ip_addr].state())
		print(scanner[ip_addr].all_protocols())
		print("open ports:",scanner[ip_addr][resp_dict[resp][1]].keys())









