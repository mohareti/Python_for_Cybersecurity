from scapy.all import *

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print(f"IP: {src_ip} -> {dst_ip}, Protocol: {proto}")

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"  TCP: {src_port} -> {dst_port}")
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"  UDP: {src_port} -> {dst_port}")

        print(f"  Payload: {packet.summary()}")
        print("-" * 50)

def sniff_network():
    print("Starting network sniffer. Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    sniff_network()
