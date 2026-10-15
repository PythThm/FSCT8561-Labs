from scapy.all import IP
from scapy.all import rdpcap
from scapy.all import TCP
from scapy.all import UDP
from scapy.all import Raw
from scapy.all import PcapReader

packets = rdpcap("botnet-capture-20110812-rbot.pcap")

tcp_packets = []

# Part 2
packets[0].show()

pkt = packets[0]
print("Contains IPv4?", IP in pkt)

if IP in pkt:
    print("Source IP:", pkt[IP].src)
    print("Destination IP:", pkt[IP].dst)

shown = 0
for pkt in packets:
    if IP in pkt:
        print(pkt[IP].src, "->", pkt[IP].dst)
        shown = shown + 1
        if shown == 5:
            break

if len(tcp_packets) > 0:
    pkt = tcp_packets[0]
    print("TCP flags:", pkt[TCP].flags)

pkt = packets[0]
print("Size (bytes):", len(pkt))
print("Timestamp:", float(pkt.time))

shown = 0
for pkt in packets:
    if IP in pkt:
        print("Source:", pkt[IP].src, "Destination:", pkt[IP].dst,
              "Bytes:", len(pkt), "Time:", float(pkt.time))
        shown = shown + 1
        if shown == 5:
            break

        
