from scapy.all import PcapReader
from scapy.all import IP
from scapy.all import TCP
from scapy.all import UDP

# Open the PCAP without loading the entire file into memory
with PcapReader("botnet-capture-20110812-rbot.pcap") as pcap_reader:
    # Store timestamps for each source IP
    recent_packets = {}
    
    # Store IPs that have already triggered an alert
    alerted_ips = set()

    # Initialize counters
    tcp_count = 0
    udp_count = 0

    for pkt in pcap_reader:

        # Only inspect IPv4 TCP/UDP packets
        if IP in pkt and (TCP in pkt or UDP in pkt):

            # Count TCP and UDP packets
            if TCP in pkt:
                tcp_count = tcp_count + 1
            elif UDP in pkt:
                udp_count = udp_count + 1

            # Get source IP and packet timestamp
            src_ip = pkt[IP].src
            timestamp = float(pkt.time)

            # Create a list for this IP if it does not exist
            if src_ip not in recent_packets:
                recent_packets[src_ip] = []

            # Get the timestamps for this source IP
            timestamps = recent_packets[src_ip]

            # Remove timestamps older than five seconds
            while (len(timestamps) > 0 and
                   timestamp - timestamps[0] > 5):
                timestamps.pop(0)

            # Add the current packet timestamp
            timestamps.append(timestamp)

            # Alert only once for each source IP
            if len(timestamps) > 20 and src_ip not in alerted_ips:
                print(
                    "ALERT: Unusually frequent traffic from",
                    src_ip,
                    "-",
                    len(timestamps),
                    "packets within 5 seconds"
                )

                alerted_ips.add(src_ip)

# Print final summary
print("\n--- Detection Summary ---")
print("Total TCP packets:", tcp_count)
print("Total UDP packets:", udp_count)
print("Total IPv4 TCP/UDP packets:", tcp_count + udp_count)
print("Number of suspicious IPs:", len(alerted_ips))
