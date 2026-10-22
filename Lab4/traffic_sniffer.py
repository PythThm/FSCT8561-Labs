from scapy.all import rdpcap
from scapy.all import IP
from scapy.all import TCP
from scapy.all import UDP
from scapy.all import PcapReader

# Part 1: Open the PCAP file
packets = rdpcap("botnet-capture-20110812-rbot.pcap")

# Initialize counters
tcp_count = 0
udp_count = 0
shown = 0

# Part 2: Process packets
with PcapReader("botnet-capture-20110812-rbot.pcap") as packet:
    for pkt in packets:
        if IP in pkt:
            if TCP in pkt:
                tcp_count = tcp_count + 1
            elif UDP in pkt:
                udp_count = udp_count + 1

            # Print the first 20 IPv4 TCP/UDP packets
            if (TCP in pkt or UDP in pkt) and shown < 20:
                if TCP in pkt:
                    protocol = "TCP"
                    source_port = pkt[TCP].sport
                    destination_port = pkt[TCP].dport
                else:
                    protocol = "UDP"
                    source_port = pkt[UDP].sport
                    destination_port = pkt[UDP].dport

                print(
                    "Source:", pkt[IP].src,
                    "Destination:", pkt[IP].dst,
                    "Protocol:", protocol,
                    "Source port:", source_port,
                    "Destination port:", destination_port
                )

                shown = shown + 1

# Part 3: Print the final summary
print("\nTotal TCP packets:", tcp_count)
print("Total UDP packets:", udp_count)
print("Total IPv4 TCP/UDP packets:", tcp_count + udp_count)
print("Packets displayed:", shown)