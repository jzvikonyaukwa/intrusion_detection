# from scapy.all import *
# import time
# import random
# import socket
# import os
# import numpy as np

# def resolve_ip(hostname):
#     try:
#         return socket.gethostbyname(hostname)
#     except socket.gaierror:
#         print(f"Error: Could not resolve hostname {hostname}")
#         return None

# def add_custom_tag(packet, tag="Scapy-Generated"):
#     packet = packet / Raw(load=tag)
#     return packet

# def generate_packet_length():
#     return random.randint(40, 1500)

# def generate_attack_packet(target_ip, target_port, attack_type, pkt_length, protocol='TCP'):
#     if protocol == 'TCP':
#         packet = IP(dst=target_ip) / TCP(dport=target_port, flags="PA") / Raw(load=f"{attack_type} payload")
#     elif protocol == 'UDP':
#         packet = IP(dst=target_ip) / UDP(dport=target_port) / Raw(load=f"{attack_type} payload")
#     packet = add_custom_tag(packet, tag=attack_type)
#     packet[IP].len = pkt_length
#     return packet

# # Example features generation for packets (you may need to adapt these to match CICIDS2018 dataset more closely)
# def generate_features():
#     features = {
#         "flow_duration": random.randint(1000, 1000000),  # in microseconds
#         "total_fwd_packets": random.randint(1, 1000),
#         "total_bwd_packets": random.randint(1, 1000),
#         "total_length_fwd_packets": random.uniform(0, 100000),
#         "total_length_bwd_packets": random.uniform(0, 100000),
#         "fwd_packet_length_max": random.uniform(0, 1500),
#         "fwd_packet_length_min": random.uniform(0, 1500),
#         "fwd_packet_length_mean": random.uniform(0, 1500),
#         "fwd_packet_length_std": random.uniform(0, 1500),
#         "bwd_packet_length_max": random.uniform(0, 1500),
#         "bwd_packet_length_min": random.uniform(0, 1500),
#         "bwd_packet_length_mean": random.uniform(0, 1500),
#         "bwd_packet_length_std": random.uniform(0, 1500),
#         "flow_bytes_per_s": random.uniform(0, 10000),
#         "flow_packets_per_s": random.uniform(0, 1000),
#         "fwd_iat_total": random.uniform(0, 100000),
#         "fwd_iat_mean": random.uniform(0, 100000),
#         "fwd_iat_std": random.uniform(0, 100000),
#         "fwd_iat_max": random.uniform(0, 100000),
#         "fwd_iat_min": random.uniform(0, 100000),
#         "bwd_iat_total": random.uniform(0, 100000),
#         "bwd_iat_mean": random.uniform(0, 100000),
#         "bwd_iat_std": random.uniform(0, 100000),
#         "bwd_iat_max": random.uniform(0, 100000),
#         "bwd_iat_min": random.uniform(0, 100000),
#         "fwd_psh_flags": random.randint(0, 1),
#         "bwd_psh_flags": random.randint(0, 1),
#         "fwd_urg_flags": random.randint(0, 1),
#         "bwd_urg_flags": random.randint(0, 1),
#         "fwd_header_length": random.randint(0, 100),
#         "bwd_header_length": random.randint(0, 100),
#         "fwd_packets_per_s": random.uniform(0, 1000),
#         "bwd_packets_per_s": random.uniform(0, 1000),
#         "packet_length_min": random.uniform(0, 1500),
#         "packet_length_max": random.uniform(0, 1500),
#         "packet_length_mean": random.uniform(0, 1500),
#         "packet_length_std": random.uniform(0, 1500),
#         "packet_length_variance": random.uniform(0, 1500),
#     }
#     return features

# # Bot attack simulation
# def simulate_bot_attack(target_ip, target_port, count=100):
#     if target_ip:
#         for _ in range(count):
#             pkt_length = generate_packet_length()
#             packet = generate_attack_packet(target_ip, target_port, "Bot", pkt_length)
#             send(packet, verbose=0)
#         print(f"Sent {count} Bot attack packets to {target_ip}:{target_port}")

# # Brute Force attack simulation
# def simulate_brute_force_attack(target_ip, target_port, count=100):
#     if target_ip:
#         for _ in range(count):
#             pkt_length = generate_packet_length()
#             packet = generate_attack_packet(target_ip, target_port, "Brute Force", pkt_length)
#             send(packet, verbose=0)
#             time.sleep(0.5)  # Simulate delay for brute force attack
#         print(f"Sent {count} Brute Force attack packets to {target_ip}:{target_port}")

# # DDoS attack simulation
# def simulate_ddos_attack(target_ip, target_port, count=1000):
#     if target_ip:
#         for _ in range(count):
#             pkt_length = generate_packet_length()
#             packet = generate_attack_packet(target_ip, target_port, "DDoS", pkt_length, protocol='UDP')
#             send(packet, verbose=0)
#         print(f"Sent {count} DDoS attack packets to {target_ip}:{target_port}")

# # DoS attack simulation
# def simulate_dos_attack(target_ip, target_port, count=100):
#     if target_ip:
#         for _ in range(count):
#             pkt_length = generate_packet_length()
#             packet = generate_attack_packet(target_ip, target_port, "DoS", pkt_length)
#             send(packet, verbose=0)
#             time.sleep(0.1)  # Simulate delay for DoS attack
#         print(f"Sent {count} DoS attack packets to {target_ip}:{target_port}")

# # Infiltration attack simulation
# def simulate_infiltration_attack(target_ip, target_port, count=50):
#     if target_ip:
#         for _ in range(count):
#             pkt_length = generate_packet_length()
#             packet = generate_attack_packet(target_ip, target_port, "Infiltration", pkt_length)
#             send(packet, verbose=0)
#             time.sleep(0.2)
#         print(f"Sent {count} Infiltration attack packets to {target_ip}:{target_port}")

# # SQL Injection attack simulation
# def simulate_sql_injection_attack(target_ip):
#     if target_ip:
#         payload = "GET /?id=1' OR '1'='1 HTTP/1.1\r\nHost: " + target_ip + "\r\n\r\n"
#         packet = IP(dst=target_ip) / TCP(dport=80) / Raw(load=payload)
#         packet = add_custom_tag(packet, tag="SQL Injection")
#         send(packet)
#         print(f"Sent SQL Injection payload to {target_ip}")

# def main():
#     hostname = os.getenv('TARGET_IP', 'capture_and_log')
#     target_ip = resolve_ip(hostname)
#     target_port = int(os.getenv('TARGET_PORT', 80))

#     attack_functions = [
#         simulate_bot_attack,
#         simulate_brute_force_attack,
#         simulate_ddos_attack,
#         simulate_dos_attack,
#         simulate_infiltration_attack,
#         simulate_sql_injection_attack
#     ]

#     if target_ip:
#         for _ in range(10):  # Number of iterations for generating random attacks
#             attack_function = random.choice(attack_functions)
#             if attack_function == simulate_sql_injection_attack:
#                 attack_function(target_ip)
#             else:
#                 attack_function(target_ip, target_port)
#             time.sleep(2)  # Delay between attacks

# if __name__ == "__main__":
#     main()



from scapy.all import *
import time
import random
import socket
import os

def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        print(f"Error: Could not resolve hostname {hostname}")
        return None

def add_custom_tag(packet):
    packet = packet / Raw(load="Scapy-Generated")
    return packet

def send_icmp_echo_request(target_ip):
    if target_ip:
        packet = IP(dst=target_ip) / ICMP()
        packet = add_custom_tag(packet)
        send(packet)
        print(f"Sent ICMP Echo Request to {target_ip}")

def send_tcp_syn(target_ip, target_port):
    if target_ip:
        packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
        packet = add_custom_tag(packet)
        send(packet)
        print(f"Sent TCP SYN to {target_ip}:{target_port}")

def send_udp_packet(target_ip, target_port, message):
    if target_ip:
        packet = IP(dst=target_ip) / UDP(dport=target_port) / Raw(load=message)
        packet = add_custom_tag(packet)
        send(packet)
        print(f"Sent UDP packet to {target_ip}:{target_port} with message: {message}")

# Bot attack simulation
def simulate_bot_attack(target_ip, target_port, count=100):
    if target_ip:
        for _ in range(count):
            packet = IP(dst=target_ip) / TCP(dport=target_port, flags="PA") / Raw(load="Botnet attack payload")
            packet = add_custom_tag(packet)
            send(packet, verbose=0)
        print(f"Sent {count} Bot attack packets to {target_ip}:{target_port}")

# Brute Force attack simulation
def simulate_brute_force_attack(target_ip, target_port, count=100):
    if target_ip:
        for _ in range(count):
            packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
            packet = add_custom_tag(packet)
            send(packet, verbose=0)
            time.sleep(0.5)
        print(f"Sent {count} Brute Force attack packets to {target_ip}:{target_port}")

# DDoS attack simulation
def simulate_ddos_attack(target_ip, target_port, count=1000):
    if target_ip:
        for _ in range(count):
            packet = IP(dst=target_ip) / UDP(dport=target_port) / Raw(load="DDoS Attack")
            packet = add_custom_tag(packet)
            send(packet, verbose=0)
        print(f"Sent {count} DDoS attack packets to {target_ip}:{target_port}")

# DoS attack simulation
def simulate_dos_attack(target_ip, target_port, count=100):
    if target_ip:
        for _ in range(count):
            packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
            packet = add_custom_tag(packet)
            send(packet, verbose=0)
            time.sleep(0.1)
        print(f"Sent {count} DoS attack packets to {target_ip}:{target_port}")

# Infiltration attack simulation
def simulate_infiltration_attack(target_ip, target_port, count=50):
    if target_ip:
        for _ in range(count):
            packet = IP(dst=target_ip) / TCP(dport=target_port, flags="PA") / Raw(load="Infiltration payload")
            packet = add_custom_tag(packet)
            send(packet, verbose=0)
            time.sleep(0.2)
        print(f"Sent {count} Infiltration attack packets to {target_ip}:{target_port}")

# SQL Injection attack simulation
def simulate_sql_injection_attack(target_ip):
    if target_ip:
        payload = "GET /?id=1' OR '1'='1 HTTP/1.1\r\nHost: " + target_ip + "\r\n\r\n"
        packet = IP(dst=target_ip) / TCP(dport=80) / Raw(load=payload)
        packet = add_custom_tag(packet)
        send(packet)
        print(f"Sent SQL Injection payload to {target_ip}")

def main():
    hostname = os.getenv('TARGET_IP', 'capture_and_log')
    target_ip = resolve_ip(hostname)
    target_port = int(os.getenv('TARGET_PORT', 80))

    attack_functions = [
        simulate_bot_attack,
        simulate_brute_force_attack,
        simulate_ddos_attack,
        simulate_dos_attack,
        simulate_infiltration_attack,
        simulate_sql_injection_attack
    ]

    if target_ip:
        for _ in range(10):  # Number of iterations for generating random attacks
            attack_function = random.choice(attack_functions)
            if attack_function == simulate_sql_injection_attack:
                attack_function(target_ip)
            else:
                attack_function(target_ip, target_port)
            time.sleep(2)  # Delay between attacks
if __name__ == "__main__":
    main()
