from scapy.all import *
import pandas as pd
import numpy as np
from collections import deque
import joblib  # Assuming your model is saved using joblib

# Load your pre-trained model
model = joblib.load('XGBoost_model.pkl')

features = [
    "Pkt Len Max", "Fwd Pkts/s", "Dst Port", "Subflow Fwd Byts", "Protocol", "TotLen Fwd Pkts",
    "Bwd Seg Size Avg", "Bwd Pkts/s", "Fwd Seg Size Avg", "Pkt Len Var", "Bwd Pkt Len Min", "Tot Fwd Pkts",
    "Pkt Len Mean", "Pkt Len Std", "Active Mean", "RST Flag Cnt", "Subflow Fwd Pkts", "Pkt Size Avg",
    "PSH Flag Cnt", "Bwd IAT Std", "ACK Flag Cnt", "Fwd Pkt Len Std", "Active Max", "Scapy Generated"
]

# Initialize variables for feature calculation
prev_packet_time = None
fwd_pkts = 0
bwd_pkts = 0
fwd_pkt_lens = []
bwd_pkt_lens = []
active_times = deque(maxlen=1000)  # Store a window of active times to compute statistics

def extract_features(packet):
    global prev_packet_time, fwd_pkts, bwd_pkts, fwd_pkt_lens, bwd_pkt_lens, active_times
    try:
        current_time = packet.time
        pkt_len = len(packet)
        protocol = packet.proto
        dst_port = packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else 0

        rst_flag = 1 if packet.haslayer(TCP) and packet[TCP].flags == 'R' else 0
        psh_flag = 1 if packet.haslayer(TTCP) and packet[TCP].flags == 'P' else 0
        ack_flag = 1 if packet.haslayer(TCP) and packet[TCP].flags == 'A' else 0

        if packet[IP].src == 'source_ip':  # Replace 'source_ip' with the actual source IP
            fwd_pkts += 1
            fwd_pkt_lens.append(pkt_len)
        else:
            bwd_pkts += 1
            bwd_pkt_lens.append(pkt_len)

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

        # Check if the packet contains the custom tag
        scapy_generated = False
        if Raw in packet and b'Scapy-Generated' in packet[Raw].load:
            scapy_generated = True

        feature_dict = {
            "Pkt Len Max": pkt_len,
            "Fwd Pkts/s": fwd_pkts_s,
            "Dst Port": dst_port,
            "Subflow Fwd Byts": tot_len_fwd_pkts,
            "Protocol": protocol,
            "TotLen Fwd Pkts": tot_len_fwd_pkts,
            "Bwd Seg Size Avg": bwd_pkt_len_avg,
            "Bwd Pkts/s": bwd_pkts_s,
            "Fwd Seg Size Avg": fwd_pkt_len_avg,
            "Pkt Len Var": pkt_len_var,
            "Bwd Pkt Len Min": bwd_pkt_len_min,
            "Tot Fwd Pkts": fwd_pkts,
            "Pkt Len Mean": pkt_len_avg,
            "Pkt Len Std": pkt_len_std,
            "Active Mean": active_mean,
            "RST Flag Cnt": rst_flag,
            "Subflow Fwd Pkts": fwd_pkts,
            "Pkt Size Avg": pkt_len_avg,
            "PSH Flag Cnt": psh_flag,
            "Bwd IAT Std": bwd_iat_std,
            "ACK Flag Cnt": ack_flag,
            "Fwd Pkt Len Std": fwd_pkt_len_std,
            "Active Max": active_max,
            "Scapy Generated": scapy_generated
        }
        return feature_dict
    except AttributeError:
        return None

def process_packet(packet):
    features = extract_features(packet)
    if features:
        features_df = pd.DataFrame([features])
        prediction = model.predict(features_df[features_df.columns.intersection(features)].values)
        print(f"Prediction: {prediction}")

def capture_packets():
    sniff(prn=process_packet, filter="ip", store=0)

if __name__ == "__main__":
    capture_packets()
