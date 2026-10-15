from scapy.all import IP
from scapy.all import rdpcap
from scapy.all import TCP
from scapy.all import UDP
from scapy.all import Raw
from scapy.all import PcapReader

packets = rdpcap("botnet-capture-20110812-rbot.pcap")

tcp_packets = []

# Part 1
print("Number of packets:", len(packets))

print(packets[0].summary())


with PcapReader("botnet-capture-20110812-rbot.pcap") as packet:
    for pkt in packets[:5]:
        print(pkt.summary())

pkt = packets[0]
print("Is this TCP?", TCP in pkt)

with PcapReader("botnet-capture-20110812-rbot.pcap") as packet:
    for pkt in packets:
        if TCP in pkt:
            tcp_packets.append(pkt)

print("TCP packets:", len(tcp_packets))

with PcapReader("botnet-capture-20110812-rbot.pcap") as packet:
    for pkt in tcp_packets[:50]:    
        print(pkt.summary())

if len(tcp_packets) > 0:
    pkt = tcp_packets[0]
    print("Source port:", pkt[TCP].sport)
    print("Destination port:", pkt[TCP].dport)

    http_packets = []


with PcapReader("botnet-capture-20110812-rbot.pcap") as packet:
    for pkt in tcp_packets:
        if pkt[TCP].sport == 80 or pkt[TCP].dport == 80:
            http_packets.append(pkt)

print("TCP port 80 packets:", len(http_packets))
with PcapReader("botnet-capture-20110812-rbot.pcap") as packet:
    for pkt in http_packets[:50]:
        print(pkt.summary())


dns_packets = []
with PcapReader("botnet-capture-20110812-rbot.pcap") as packet:
    for pkt in packets:
        if UDP in pkt:
            if pkt[UDP].sport == 53 or pkt[UDP].dport == 53:
                dns_packets.append(pkt)

print("UDP port 53 packets:", len(dns_packets))
with PcapReader("botnet-capture-20110812-rbot.pcap") as packet:
    for pkt in dns_packets[:50]:
        print(pkt.summary())

