from scapy.all import IP
from scapy.all import rdpcap
from scapy.all import TCP
from scapy.all import UDP
from scapy.all import Raw
from scapy.all import PcapReader

packets = rdpcap("botnet-capture-20110812-rbot.pcap")

tcp_packets = []

# Part 3 
pkt = packets[0]
print("Contains Raw payload?", Raw in pkt)

if Raw in pkt:
    print(repr(bytes(pkt[Raw].load)[:80]))
else:
    print("No Raw payload in this packet")

with PcapReader("botnet-capture-20110812-rbot.pcap") as packet:
    for pkt in packets:
        if Raw in pkt:
            print("Payload sample:", repr(bytes(pkt[Raw].load)[:80]))
            break

with PcapReader("botnet-capture-20110812-rbot.pcap") as packet:
    for pkt in packets:
        if Raw in pkt:
            sample = bytes(pkt[Raw].load)[:80]
            print(sample.decode("utf-8", errors="replace"))
            break

with PcapReader("botnet-capture-20110812-rbot.pcap") as packet:
    found = False
    for pkt in packets[:500]:
        if Raw in pkt:
            data = bytes(pkt[Raw].load)
            if b"User-Agent:" in data:
                print("Possible plaintext HTTP header found")
                found = True
                break
    if not found:
        print("No matching header found in the first 500 packets")
