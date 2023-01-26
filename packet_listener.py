import scapy.all as scapy
from scapy_http import http
import optparse

#parse_object = optparse.OptionParser()
#parse_object.add_option("-i","--interface",dest="interface",help="Enter The İnterface")
#interface1=parse_object.parse_args()
#user_interface=interface1.interface

interface_choose=input("İnterface: ")

print("Targer Sniffing")

def listen_packets(interface):
    scapy.sniff(iface=interface_choose,store=False,prn=analyze_packets)
    #prn = callback function

def analyze_packets(packet):
    packet.show()
#    if packet.haslayer(http.HTTPRequest):
#        if packet.haslayer(scapy.Raw):
#            print(packet[scapy.Raw].load)

listen_packets(interface_choose)
