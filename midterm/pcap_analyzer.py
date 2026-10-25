import os
from collections import deque

from scapy.all import IP, TCP, UDP, PcapReader

# fixed path to prevent traversal to other files
PCAP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "FSCT8561_Operation_Sentinel_Traffic.pcap")

WINDOW_SECONDS = 5
ALERT_THRESHOLD = 20          # alert when MORE than this many packets fall in the window
PACKETS_LISTED = 20
MAX_ALERTS_SHOWN = 50
MAX_TRACKED_IPS = 10000       # limits memory if a capture holds many (spoofed) sources
MAX_PCAP_BYTES = 200 * 1024 * 1024


class PcapUnavailable(Exception):
    """The capture is missing, too large, unreadable or corrupt."""


def analyze_pcap(path=PCAP_PATH):
    """Read the capture once and return the result as plain text."""
    if not os.path.isfile(path):
        raise PcapUnavailable("capture file not found")
    if os.path.getsize(path) > MAX_PCAP_BYTES:
        raise PcapUnavailable("capture file exceeds the size limit")

    tcp_count = 0
    udp_count = 0
    first_packets = []
    windows = {}              # source IP -> deque of recent packet timestamps
    alerted = set()
    alerts = []               # (source IP, packets in window, packet number)
    tracking_limited = False

    try:
        with PcapReader(path) as reader:
            for number, pkt in enumerate(reader, start=1):
                # Only IPv4 TCP/UDP is inspected; anything else is skipped, not an error.
                if IP not in pkt or not (TCP in pkt or UDP in pkt):
                    continue

                if TCP in pkt:
                    tcp_count += 1
                    protocol, layer = "TCP", pkt[TCP]
                else:
                    udp_count += 1
                    protocol, layer = "UDP", pkt[UDP]

                src = pkt[IP].src
                if len(first_packets) < PACKETS_LISTED:
                    first_packets.append(
                        f"{src}:{layer.sport} -> {pkt[IP].dst}:{layer.dport} {protocol}"
                    )

                # Sliding window: forget timestamps older than 5 seconds.
                if src not in windows:
                    if len(windows) >= MAX_TRACKED_IPS:
                        tracking_limited = True
                        continue
                    windows[src] = deque()
                timestamps = windows[src]
                now = float(pkt.time)
                while timestamps and now - timestamps[0] > WINDOW_SECONDS:
                    timestamps.popleft()
                timestamps.append(now)

                if len(timestamps) > ALERT_THRESHOLD and src not in alerted:
                    alerted.add(src)
                    alerts.append((src, len(timestamps), number))
    except PcapUnavailable:
        raise
    except Exception as error:
        # Corrupt or truncated capture. The caller logs the type; the client sees a generic error.
        raise PcapUnavailable(f"capture could not be parsed ({type(error).__name__})")

    return _format_report(os.path.basename(path), tcp_count, udp_count,
                          first_packets, alerts, tracking_limited)


def _format_report(name, tcp_count, udp_count, first_packets, alerts, tracking_limited):
    lines = [
        f"PCAP analysis: {name}",
        f"Total TCP packets: {tcp_count}",
        f"Total UDP packets: {udp_count}",
        f"Total IPv4 TCP/UDP packets: {tcp_count + udp_count}",
        "",
        f"First {len(first_packets)} TCP/UDP packets:",
    ]
    lines += [f"  {i}. {text}" for i, text in enumerate(first_packets, start=1)]
    lines += ["", f"Detection rule: more than {ALERT_THRESHOLD} packets from one source IP "
                  f"within {WINDOW_SECONDS} seconds"]

    for src, count, number in alerts[:MAX_ALERTS_SHOWN]:
        lines.append(f"ALERT: Unusually frequent traffic from {src} - {count} packets "
                     f"within {WINDOW_SECONDS} seconds (threshold crossed at packet #{number})")
    if len(alerts) > MAX_ALERTS_SHOWN:
        lines.append(f"... {len(alerts) - MAX_ALERTS_SHOWN} more alerts not shown")
    if tracking_limited:
        lines.append(f"Note: more than {MAX_TRACKED_IPS} source IPs; later sources were not tracked")

    lines.append(f"Suspicious source IPs: {len(alerts)}")
    return "\n".join(lines)