"""
Simple Packet Sniffer Tool

Captures network packets and displays:
  - Source and destination IP addresses
  - Protocol type (TCP/UDP/ICMP/Other)
  - Port information (when applicable)
  - Payload data (first bytes)

Usage:
  sudo python3 packet_sniffer.py [-i INTERFACE] [-c COUNT] [-f FILTER]

Requires root privileges to capture live packets.
"""
import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


def packet_callback(packet):
    # Only process IP packets
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto
        proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto_num, str(proto_num))

        # Print basic IP and protocol info
        print(f"[{proto_name}] {src_ip} -> {dst_ip}")

        # Detailed transport layer info
        if proto_name == 'TCP' and packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"    Ports: {tcp_layer.sport} -> {tcp_layer.dport}")
        elif proto_name == 'UDP' and packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"    Ports: {udp_layer.sport} -> {udp_layer.dport}")
        elif proto_name == 'ICMP' and packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            print(f"    ICMP Type: {icmp_layer.type}")

        # Show payload data (first 50 bytes)
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            # Safely display raw bytes
            preview = raw_data[:50]
            more = '...' if len(raw_data) > 50 else ''
            print(f"    Payload: {preview!r} {more}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer Tool")
    parser.add_argument('-i', '--interface', help='Network interface to sniff on (e.g., eth0)', default=None)
    parser.add_argument('-c', '--count', type=int, default=0,
                        help='Number of packets to capture (0 for infinite)')
    parser.add_argument('-f', '--filter', type=str, default='',
                        help='BPF filter string (e.g., "tcp port 80")')
    args = parser.parse_args()

    # Prepare sniff parameters
    sniff_kwargs = {
        'iface': args.interface,
        'count': args.count,             # Always an integer (0 = infinite)
        'prn': packet_callback,
        'store': False
    }
    if args.filter:
        sniff_kwargs['filter'] = args.filter

    try:
        sniff(**sniff_kwargs)
    except PermissionError:
        print("Error: Insufficient permissions. Try running with sudo/root.")
    except Exception as e:
        print(f"Error during packet capture: {e}")


if __name__ == '__main__':
    main()
