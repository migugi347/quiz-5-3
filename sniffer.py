#!/bin/env python3
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import ICMP
from scapy.layers.inet import Ether


def main():
    """Driver function"""
    while True:
        print_menu()
        option = input('Choose a menu option: ')
        if option == '1':
            print("Creating and sending packets ...")

            # creating packet
            pkt_sent = Ether()/IP()/ ICMP()
            pkt_sent[Ether].dst = "00:02:15:37:a2:44"
            pkt_sent[Ether].src = "00:ae:f3:52:aa:d1"


            pkt_sent[IP].dst = "192.168.6.12"
            pkt_sent[IP].src = "192.168.10.4"
            pkt_sent[IP].ttl = 42
            pkt_sent[IP].proto = ICMP

            pkt_sent[ICMP].type =42

            pkt_sent[Raw].load = 


        elif option == '2':
            print("Listening to all traffic and show all ...")
            print("lISTENING TO ALL TRAFFIC.........")

            # can be lo or etho0
            sniff(iface="lo", prn=lambda x: x.show())

        elif option == '3':
            print("Listening to ping command to the address 8.8.4.4 ...")
            print("lISTENING TO PING from 8.8.4.4.........")

            sniff(filter="host 8.8.4.4", prn=print_pkt)

        elif option == '4':
            print("Listening to telnet command executed from localhost ...")

            sniff(filter="port 8080", prn=print_pkt)

        elif option == '5':
            print("End")
            break
        else:
            print(f"\nInvalid entry\n")


def send_pkt(count, interval):
    """Send a custom packet count many times with interval between """
    print(":::Sending ", count, " packets:::")


""" Print Source IP, Destination IP, Protocol, TTL"""


def print_pkt(pkt):

    print("Source IP:: ", pkt[IP].src)
    print("Destination IP:: ", pkt[IP].dst)
    print("Protocol:: ", pkt[IP].proto)
    print("TTL  :: ", pkt[IP].ttl)
    print("\n")


def print_menu():
    """Prints the menu of options"""
    print("*******************Main Menu*******************")
    print('1. Create and send packets')
    print('2. Listen to all traffic and show all')
    print('3. Listen to ping command to the address 8.8.4.4')
    print('4. Listen to telnet command executed from localhost')
    print('5. Quit')
    print('***********************************************\n')


main()
