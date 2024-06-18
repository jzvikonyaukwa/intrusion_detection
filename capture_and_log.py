import pyshark
import os
import logging
from collections import deque
import numpy as np

# Configure logging
logging.basicConfig(filename='packet_logs.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Initialize variables for feature calculation
flow_start_time = None
fwd_pkts = 0
bwd_pkts = 0
fwd_pkt_lens = []
bwd_pkt_lens = []
flow_durations = deque(maxlen=1000)
active_times = deque(maxlen=1000)  # Store a window of active times to compute statistics

def calculate_features(packet, current_time):
    global flow_start_time, fwd_pkts, bwd_pkts, fwd_pkt_lens, bwd_pkt_lens, flow_durations, active_times

    if flow_start_time is None:
        flow_start_time = current_time

    flow_duration = (current_time - flow_start_time) * 1000000  # in microseconds
    flow_durations.append(flow_duration)

    if not hasattr(packet, 'ip'):
        return None  # Skip packets without IP layer

    src_ip = packet.ip.src

    if src_ip == 'source_ip':  # Replace 'source_ip' with the actual source IP
        fwd_pkts += 1
        fwd_pkt_lens.append(len(packet))
    else:
        bwd_pkts += 1
        bwd_pkt_lens.append(len(packet))

    fwd_pkt_len_avg = np.mean(fwd_pkt_lens) if fwd_pkt_lens else 0
    fwd_pkt_len_var = np.var(fwd_pkt_lens) if fwd_pkt_lens else 0
    fwd_pkt_len_std = np.std(fwd_pkt_lens) if fwd_pkt_lens else 0

    bwd_pkt_len_avg = np.mean(bwd_pkt_lens) if bwd_pkt_lens else 0
    bwd_pkt_len_min = np.min(bwd_pkt_lens) if bwd_pkt_lens else 0
    bwd_pkt_len_std = np.std(bwd_pkt_lens) if bwd_pkt_lens else 0

    pkt_len_avg = np.mean(fwd_pkt_lens + bwd_pkt_lens) if fwd_pkt_lens + bwd_pkt_lens else 0
    pkt_len_var = np.var(fwd_pkt_lens + bwd_pkt_lens) if fwd_pkt_lens + bwd_pkt_lens else 0
    pkt_len_std = np.std(fwd_pkt_lens + bwd_pkt_lens) if fwd_pkt_lens + bwd_pkt_lens else 0

    total_time = current_time - (active_times[0] if active_times else current_time)
    fwd_pkts_s = fwd_pkts / total_time if total_time > 0 else 0
    bwd_pkts_s = bwd_pkts / total_time if total_time > 0 else 0

    tot_len_fwd_pkts = sum(fwd_pkt_lens)
    tot_len_bwd_pkts = sum(bwd_pkt_lens)

    active_mean = np.mean(active_times) if active_times else 0
    active_max = np.max(active_times) if active_times else 0
    bwd_iat_std = np.std(np.diff(list(active_times))) if len(active_times) > 1 else 0

    transport_layer = packet.transport_layer
    if transport_layer == 'TCP' and hasattr(packet, 'tcp'):
        flags = packet.tcp.flags
        fwd_psh_flags = 1 if 'PSH' in flags else 0
        bwd_psh_flags = 1 if 'PSH' in flags else 0
        fwd_urg_flags = 1 if 'URG' in flags else 0
        bwd_urg_flags = 1 if 'URG' in flags else 0
    else:
        fwd_psh_flags = 0
        bwd_psh_flags = 0
        fwd_urg_flags = 0
        bwd_urg_flags = 0

    return {
        "flow_duration": flow_duration,
        "total_fwd_packets": fwd_pkts,
        "total_bwd_packets": bwd_pkts,
        "total_length_fwd_packets": tot_len_fwd_pkts,
        "total_length_bwd_packets": tot_len_bwd_pkts,
        "fwd_packet_length_max": np.max(fwd_pkt_lens) if fwd_pkt_lens else 0,
        "fwd_packet_length_min": np.min(fwd_pkt_lens) if fwd_pkt_lens else 0,
        "fwd_packet_length_mean": fwd_pkt_len_avg,
        "fwd_packet_length_std": fwd_pkt_len_std,
        "bwd_packet_length_max": np.max(bwd_pkt_lens) if bwd_pkt_lens else 0,
        "bwd_packet_length_min": bwd_pkt_len_min,
        "bwd_packet_length_mean": bwd_pkt_len_avg,
        "bwd_packet_length_std": bwd_pkt_len_std,
        "flow_bytes_per_s": (tot_len_fwd_pkts + tot_len_bwd_pkts) / (total_time * 1000000) if total_time > 0 else 0,
        "flow_packets_per_s": (fwd_pkts + bwd_pkts) / (total_time * 1000000) if total_time > 0 else 0,
        "fwd_iat_total": sum(np.diff(fwd_pkt_lens)) if len(fwd_pkt_lens) > 1 else 0,
        "fwd_iat_mean": np.mean(np.diff(fwd_pkt_lens)) if len(fwd_pkt_lens) > 1 else 0,
        "fwd_iat_std": np.std(np.diff(fwd_pkt_lens)) if len(fwd_pkt_lens) > 1 else 0,
        "fwd_iat_max": np.max(np.diff(fwd_pkt_lens)) if len(fwd_pkt_lens) > 1 else 0,
        "fwd_iat_min": np.min(np.diff(fwd_pkt_lens)) if len(fwd_pkt_lens) > 1 else 0,
        "bwd_iat_total": sum(np.diff(bwd_pkt_lens)) if len(bwd_pkt_lens) > 1 else 0,
        "bwd_iat_mean": np.mean(np.diff(bwd_pkt_lens)) if len(bwd_pkt_lens) > 1 else 0,
        "bwd_iat_std": np.std(np.diff(bwd_pkt_lens)) if len(bwd_pkt_lens) > 1 else 0,
        "bwd_iat_max": np.max(np.diff(bwd_pkt_lens)) if len(bwd_pkt_lens) > 1 else 0,
        "bwd_iat_min": np.min(np.diff(bwd_pkt_lens)) if len(bwd_pkt_lens) > 1 else 0,
        "fwd_psh_flags": fwd_psh_flags,
        "bwd_psh_flags": bwd_psh_flags,
        "fwd_urg_flags": fwd_urg_flags,
        "bwd_urg_flags": bwd_urg_flags,
        "fwd_header_length": len(packet[transport_layer]) if transport_layer and hasattr(packet, transport_layer) and not isinstance(packet[transport_layer], pyshark.packet.layers.json_layer.JsonLayer) else 0,
        "bwd_header_length": len(packet[transport_layer]) if transport_layer and hasattr(packet, transport_layer) and not isinstance(packet[transport_layer], pyshark.packet.layers.json_layer.JsonLayer) else 0,
        "fwd_packets_per_s": fwd_pkts_s,
        "bwd_packets_per_s": bwd_pkts_s,
        "packet_length_min": np.min(fwd_pkt_lens + bwd_pkt_lens) if fwd_pkt_lens + bwd_pkt_lens else 0,
        "packet_length_max": np.max(fwd_pkt_lens + bwd_pkt_lens) if fwd_pkt_lens + bwd_pkt_lens else 0,
        "packet_length_mean": pkt_len_avg,
        "packet_length_std": pkt_len_std,
        "packet_length_variance": pkt_len_var
    }

def capture_packets(interface='eth0'):
    def packet_callback(packet):
        try:
            current_time = packet.sniff_time.timestamp()
            features = calculate_features(packet, current_time)
            raw_packet = packet.get_raw_packet()
            raw_packet_str = raw_packet.decode(errors='ignore')
            if 'Scapy-Generated' in raw_packet_str:
                logging.info(f"ATTACK: {raw_packet_str} --> {features}")
                print(f"ATTACK: {raw_packet_str} ---> {features}")
            else:
                logging.info(f"REGULAR: {raw_packet_str}")
                print(f"REGULAR: {raw_packet_str}")
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
            print(f"Error processing packet: {e}")

    cap = pyshark.LiveCapture(interface=interface, use_json=True, include_raw=True)
    cap.apply_on_packets(packet_callback)

if __name__ == "__main__":
    interface = os.getenv('INTERFACE', 'eth0')
    capture_packets(interface)
