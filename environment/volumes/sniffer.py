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
            print('Enter number of packets:')
            number = input()
            print('Enter interval:')
            interval = input()

            # creating packet
            pkt_sent = IP() / ICMP()

            pkt_sent[IP].dst = "192.168.6.12"
            pkt_sent[IP].src = "192.168.10.4"
            pkt_sent[IP].ttl = 32

            pkt_sent[ICMP].type = 42

            send_pkt(pkt_sent, int(number), int(interval))

        elif option == '2':
            print("Listening to all traffic and show all ...")
            sniff(iface="br-a2105757dff3", prn=lambda x: x.show())

        elif option == '3':
            print("Listening to ping command to the address 8.8.4.4 ...")
            sniff(filter="icmp and host 8.8.4.4", prn=print_pkt)

        elif option == '4':
            print("Listening to telnet command executed from localhost ...")
            sniff(filter="port 23", prn=print_pkt)

        elif option == '5':
            print("End")
            break
        else:
            print(f"\nInvalid entry\n")


def send_pkt(pkt, number, interval):
    """Send a custom packet"""

    send(pkt, count=number, inter=int(interval))
    pass


def print_pkt(pkt):
    """ Print Source IP, Destination IP, Protocol, TTL"""
    print("Source IP:: ", pkt[IP].src, end="")
    print("Destination IP:: ", pkt[IP].dst, end="")
    print("Protocol:: ", pkt[IP].proto, end="")
    print("TTL  :: ", pkt[IP].ttl, end="")
    print("\n")
    pass


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
