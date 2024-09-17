import time
from flask_socketio import emit
from settings import load_settings, get_valid_interfaces
from extensions import socketio
import pyshark 
import numpy as np
from collections import defaultdict
import random
from alerts import background_alert_task
import pandas as pd
import joblib

# Load the saved model and the scaler
best_model = joblib.load('models/best_model.pkl')
scaler = joblib.load('models/scaler.pkl')

# Define the attack type mapping
attack_mapping = {
    0: 'BENIGN',
    1: 'Bot',
    2: 'Brute Force',
    3: 'DDoS',
    4: 'DoS',
    5: 'Heartbleed',
    6: 'Infiltration',
    7: 'Port Scan',
    8: 'Web Attack'
}



def extract_features(packet, flow_dict):
    feature = {}
    if hasattr(packet, 'ip'):
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        protocol = packet.transport_layer
        timestamp = float(packet.sniff_timestamp)
        length = int(packet.length)
        if protocol == 'TCP':
            dst_port = int(packet.tcp.dstport)
            flags = int(packet.tcp.flags, 16)
            hdr_len = int(packet.tcp.hdr_len)
        elif protocol == 'UDP':
            dst_port = int(packet.udp.dstport)
            flags = 0
            hdr_len = int(packet.udp.hdr_len)
        else:
            dst_port = 0
            flags = 0
            hdr_len = 0

        flow_key = (src_ip, dst_ip, protocol, dst_port)

        if flow_key not in flow_dict:
            flow_dict[flow_key] = {
                'start_time': timestamp,
                'timestamps': [],
                'lengths': [],
                'fwd_packets': 0,
                'bwd_packets': 0,
                'fwd_length': 0,
                'bwd_length': 0,
                'fwd_lengths': [],
                'bwd_lengths': [],
                'fwd_flags': [],
                'bwd_flags': [],
                'fwd_iat': [],
                'bwd_iat': [],
                'fwd_psh_flags': 0,
                'bwd_psh_flags': 0,
                'fwd_urg_flags': 0,
                'bwd_urg_flags': 0,
                'fwd_header_length': 0,
                'bwd_header_length': 0,
                'min_packet_length': float('inf'),
                'max_packet_length': 0,
                'packet_lengths': [],
                'fin_flag_count': 0,
                'syn_flag_count': 0,
                'rst_flag_count': 0,
                'psh_flag_count': 0,
                'ack_flag_count': 0,
                'urg_flag_count': 0,
                'cwe_flag_count': 0,
                'ece_flag_count': 0,
                'down_up_ratio': 0,
                'average_packet_size': 0,
                'avg_fwd_segment_size': 0,
                'avg_bwd_segment_size': 0,
                'fwd_avg_bytes_bulk': 0,
                'fwd_avg_packets_bulk': 0,
                'fwd_avg_bulk_rate': 0,
                'bwd_avg_bytes_bulk': 0,
                'bwd_avg_packets_bulk': 0,
                'bwd_avg_bulk_rate': 0,
                'subflow_fwd_packets': 0,
                'subflow_fwd_bytes': 0,
                'subflow_bwd_packets': 0,
                'subflow_bwd_bytes': 0,
                'init_win_bytes_forward': 0,
                'init_win_bytes_backward': 0,
                'act_data_pkt_fwd': 0,
                'min_seg_size_forward': 0,
                'active_mean': 0,
                'active_std': 0,
                'active_max': 0,
                'active_min': 0,
                'idle_mean': 0,
                'idle_std': 0,
                'idle_max': 0,
                'idle_min': 0,
            }

        flow = flow_dict[flow_key]

        flow['timestamps'].append(timestamp)
        flow['lengths'].append(length)
        flow['packet_lengths'].append(length)

        if src_ip == flow_key[0]:  # Forward direction
            flow['fwd_packets'] += 1
            flow['fwd_length'] += length
            flow['fwd_lengths'].append(length)
            flow['fwd_flags'].append(flags)
            flow['fwd_psh_flags'] += (flags & 0x08) >> 3
            flow['fwd_urg_flags'] += (flags & 0x20) >> 5
            flow['fwd_header_length'] += hdr_len
            flow['act_data_pkt_fwd'] += 1
            flow['min_seg_size_forward'] = min(flow['min_seg_size_forward'], length)
            if len(flow['timestamps']) > 1:
                flow['fwd_iat'].append(timestamp - flow['timestamps'][-2])
        else:  # Backward direction
            flow['bwd_packets'] += 1
            flow['bwd_length'] += length
            flow['bwd_lengths'].append(length)
            flow['bwd_flags'].append(flags)
            flow['bwd_psh_flags'] += (flags & 0x08) >> 3
            flow['bwd_urg_flags'] += (flags & 0x20) >> 5
            flow['bwd_header_length'] += hdr_len
            if len(flow['timestamps']) > 1:
                flow['bwd_iat'].append(timestamp - flow['timestamps'][-2])

        flow['min_packet_length'] = min(flow['min_packet_length'], length)
        flow['max_packet_length'] = max(flow['max_packet_length'], length)
        flow['fin_flag_count'] += (flags & 0x01)
        flow['syn_flag_count'] += (flags & 0x02) >> 1
        flow['rst_flag_count'] += (flags & 0x04) >> 2
        flow['psh_flag_count'] += (flags & 0x08) >> 3
        flow['ack_flag_count'] += (flags & 0x10) >> 4
        flow['urg_flag_count'] += (flags & 0x20) >> 5
        flow['cwe_flag_count'] += (flags & 0x40) >> 6
        flow['ece_flag_count'] += (flags & 0x80) >> 7

        feature['src_ip'] = src_ip
        feature['dst_ip'] = dst_ip
        feature['protocol'] = protocol
        feature['dst_port'] = dst_port
        feature['length'] = length
        feature['timestamp'] = timestamp
        feature['fwd_flag'] = flags if src_ip == flow_key[0] else 0
        feature['bwd_flag'] = flags if dst_ip == flow_key[1] else 0

        return feature, flow_key
    return None, None
flow_dict = defaultdict(dict)

def background_task():
    valid_interfaces = get_valid_interfaces()
    print("Valid interfaces==========> ",valid_interfaces)
    events_analyzed = 0
    detected_threats = 0
    priority_cases = 0

    while True:
        settings = load_settings()
        interface = settings.get('interface', 'eth0')
        if interface not in valid_interfaces:
            interface = 'eth0'  # Default to eth0 if the interface is invalid
        update_interval = settings.get('update_interval', 5)
        cap = pyshark.LiveCapture(interface=interface)

      
        for packet in cap.sniff_continuously(packet_count=1):
            events_analyzed += 1
            features, flow_key = extract_features(packet, flow_dict)
            if features:
                # Derive additional features for the current flow
                flow = flow_dict[flow_key]
                flow_duration = max(flow['timestamps']) - min(flow['timestamps'])
                fwd_packets = flow['fwd_packets']
                bwd_packets = flow['bwd_packets']
                total_packets = fwd_packets + bwd_packets
                fwd_length = sum(flow['fwd_lengths'])  # Sum the lengths
                bwd_length = sum(flow['bwd_lengths'])  # Sum the lengths
                total_length = fwd_length + bwd_length
                fwd_packet_length_max = max(flow['fwd_lengths']) if fwd_packets > 0 else 0
                fwd_packet_length_min = min(flow['fwd_lengths']) if fwd_packets > 0 else 0
                fwd_packet_length_mean = np.mean(flow['fwd_lengths']) if fwd_packets > 0 else 0
                fwd_packet_length_std = np.std(flow['fwd_lengths']) if fwd_packets > 0 else 0
                bwd_packet_length_max = max(flow['bwd_lengths']) if bwd_packets > 0 else 0
                bwd_packet_length_min = min(flow['bwd_lengths']) if bwd_packets > 0 else 0
                bwd_packet_length_mean = np.mean(flow['bwd_lengths']) if bwd_packets > 0 else 0
                bwd_packet_length_std = np.std(flow['bwd_lengths']) if bwd_packets > 0 else 0
                flow_bytes_per_s = total_length / flow_duration if flow_duration > 0 else 0
                flow_packets_per_s = total_packets / flow_duration if flow_duration > 0 else 0
                flow_iat_mean = np.mean(np.diff(flow['timestamps'])) if total_packets > 1 else 0
                flow_iat_std = np.std(np.diff(flow['timestamps'])) if total_packets > 1 else 0
                flow_iat_max = max(np.diff(flow['timestamps'])) if total_packets > 1 else 0
                flow_iat_min = min(np.diff(flow['timestamps'])) if total_packets > 1 else 0
                fwd_iat_total = sum(flow['fwd_iat']) if fwd_packets > 1 else 0
                fwd_iat_mean = np.mean(flow['fwd_iat']) if fwd_packets > 1 else 0
                fwd_iat_std = np.std(flow['fwd_iat']) if fwd_packets > 1 else 0
                fwd_iat_max = max(flow['fwd_iat']) if fwd_packets > 1 else 0
                fwd_iat_min = min(flow['fwd_iat']) if fwd_packets > 1 else 0
                bwd_iat_total = sum(flow['bwd_iat']) if bwd_packets > 1 else 0
                bwd_iat_mean = np.mean(flow['bwd_iat']) if bwd_packets > 1 else 0
                bwd_iat_std = np.std(flow['bwd_iat']) if bwd_packets > 1 else 0
                bwd_iat_max = max(flow['bwd_iat']) if bwd_packets > 1 else 0
                bwd_iat_min = min(flow['bwd_iat']) if bwd_packets > 1 else 0

                flow_features = {
                    'src_ip': features['src_ip'],
                    'dst_ip': features['dst_ip'],
                    'protocol': features['protocol'],
                    'Destination Port': features['dst_port'],
                    'Flow Duration': flow_duration,
                    'Total Fwd Packets': fwd_packets,
                    'Total Backward Packets': bwd_packets,
                    'Total Length of Fwd Packets': fwd_length,
                    'Total Length of Bwd Packets': bwd_length,
                    'Fwd Packet Length Max': fwd_packet_length_max,
                    'Fwd Packet Length Min': fwd_packet_length_min,
                    'Fwd Packet Length Mean': fwd_packet_length_mean,
                    'Fwd Packet Length Std': fwd_packet_length_std,
                    'Bwd Packet Length Max': bwd_packet_length_max,
                    'Bwd Packet Length Min': bwd_packet_length_min,
                    'Bwd Packet Length Mean': bwd_packet_length_mean,
                    'Bwd Packet Length Std': bwd_packet_length_std,
                    'Flow Bytes/s': flow_bytes_per_s,
                    'Flow Packets/s': flow_packets_per_s,
                    'Flow IAT Mean': flow_iat_mean,
                    'Flow IAT Std': flow_iat_std,
                    'Flow IAT Max': flow_iat_max,
                    'Flow IAT Min': flow_iat_min,
                    'Fwd IAT Total': fwd_iat_total,
                    'Fwd IAT Mean': fwd_iat_mean,
                    'Fwd IAT Std': fwd_iat_std,
                    'Fwd IAT Max': fwd_iat_max,
                    'Fwd IAT Min': fwd_iat_min,
                    'Bwd IAT Total': bwd_iat_total,
                    'Bwd IAT Mean': bwd_iat_mean,
                    'Bwd IAT Std': bwd_iat_std,
                    'Bwd IAT Max': bwd_iat_max,
                    'Bwd IAT Min': bwd_iat_min,
                    'Fwd PSH Flags': flow['fwd_psh_flags'],
                    'Bwd PSH Flags': flow['bwd_psh_flags'],
                    'Fwd URG Flags': flow['fwd_urg_flags'],
                    'Bwd URG Flags': flow['bwd_urg_flags'],
                    'Fwd Header Length': flow['fwd_header_length'],
                    'Bwd Header Length': flow['bwd_header_length'],
                    'Fwd Packets/s': fwd_packets / flow_duration if flow_duration > 0 else 0,
                    'Bwd Packets/s': bwd_packets / flow_duration if flow_duration > 0 else 0,
                    'Min Packet Length': flow['min_packet_length'],
                    'Max Packet Length': flow['max_packet_length'],
                    'Packet Length Mean': np.mean(flow['packet_lengths']) if flow['packet_lengths'] else 0,
                    'Packet Length Std': np.std(flow['packet_lengths']) if flow['packet_lengths'] else 0,
                    'Packet Length Variance': np.var(flow['packet_lengths']) if flow['packet_lengths'] else 0,
                    'FIN Flag Count': flow['fin_flag_count'],
                    'SYN Flag Count': flow['syn_flag_count'],
                    'RST Flag Count': flow['rst_flag_count'],
                    'PSH Flag Count': flow['psh_flag_count'],
                    'ACK Flag Count': flow['ack_flag_count'],
                    'URG Flag Count': flow['urg_flag_count'],
                    'CWE Flag Count': flow['cwe_flag_count'],
                    'ECE Flag Count': flow['ece_flag_count'],
                    'Down/Up Ratio': fwd_packets / bwd_packets if bwd_packets > 0 else 0,
                    'Average Packet Size': np.mean(flow['packet_lengths']) if flow['packet_lengths'] else 0,
                    'Avg Fwd Segment Size': fwd_length / fwd_packets if fwd_packets > 0 else 0,
                    'Avg Bwd Segment Size': bwd_length / bwd_packets if bwd_packets > 0 else 0,
                    'Fwd Avg Bytes/Bulk': flow['fwd_avg_bytes_bulk'],
                    'Fwd Avg Packets/Bulk': flow['fwd_avg_packets_bulk'],
                    'Fwd Avg Bulk Rate': flow['fwd_avg_bulk_rate'],
                    'Bwd Avg Bytes/Bulk': flow['bwd_avg_bytes_bulk'],
                    'Bwd Avg Packets/Bulk': flow['bwd_avg_packets_bulk'],
                    'Bwd Avg Bulk Rate': flow['bwd_avg_bulk_rate'],
                    'Subflow Fwd Packets': fwd_packets,
                    'Subflow Fwd Bytes': fwd_length,
                    'Subflow Bwd Packets': bwd_packets,
                    'Subflow Bwd Bytes': bwd_length,
                    'Init_Win_bytes_forward': flow['init_win_bytes_forward'],
                    'Init_Win_bytes_backward': flow['init_win_bytes_backward'],
                    'act_data_pkt_fwd': flow['act_data_pkt_fwd'],
                    'min_seg_size_forward': flow['min_seg_size_forward'],
                    'Active Mean': 0,
                    'Active Std': 0,
                    'Active Max': 0,
                    'Active Min': 0,
                    'Idle Mean': 0,
                    'Idle Std': 0,
                    'Idle Max': 0,
                    'Idle Min': 0,
                }
                 # List of feature names used during training
              # Correct order of feature names used during training (excluding 'Attack Type' and 'Attack Type Code')
                feature_names = [
                    "Fwd Packet Length Std", "URG Flag Count", "Bwd Packet Length Max", "Active Max", "Flow IAT Std",
                    "Packet Length Mean", "Fwd Packet Length Max", "Min Packet Length", "Init_Win_bytes_forward", 
                    "SYN Flag Count", "Idle Std", "Flow Duration", "Active Min", "Init_Win_bytes_backward", 
                    "Packet Length Std", "Fwd IAT Total", "Destination Port", "Bwd Packet Length Min", 
                    "Bwd IAT Min", "Bwd IAT Std", "Bwd Packet Length Mean", "PSH Flag Count", "Flow IAT Mean", 
                    "FIN Flag Count", "Idle Min", "Idle Mean", "Fwd IAT Max", "Bwd Packet Length Std", 
                    "Fwd Packet Length Mean", "Fwd PSH Flags", "Max Packet Length", "Flow Bytes/s", 
                    "Fwd IAT Mean", "Avg Bwd Segment Size", "Flow Packets/s", "Avg Fwd Segment Size", "Average Packet Size", 
                    "Flow IAT Max", "Bwd Packets/s", "Active Std", "Idle Max", "Bwd IAT Max", "Fwd Packet Length Min", 
                    "Fwd IAT Min", "Packet Length Variance", "ACK Flag Count", "Fwd IAT Std", "Fwd Packets/s"
                ]
                    
                 # Filter flow_features to only include the specified features
                filtered_flow_features = {k: flow_features[k] for k in feature_names if k in flow_features}

                # Create a DataFrame for the new data
                X_real = pd.DataFrame([filtered_flow_features])
                # data_list = X_real.to_dict(orient='records')
                # print(data_list)
                # Ensure the order of columns in X_real matches the order of feature_names
                X_real = X_real[feature_names]

                # Scale the real data
                X_real_scaled = scaler.transform(X_real)

                # Predict using the loaded model
                y_real_pred = best_model.predict(X_real_scaled)

                attack_predictions = [attack_mapping[label] for label in y_real_pred]

                # Add prediction to flow_features
                filtered_flow_features['attack_type'] = attack_predictions[0]
                filtered_flow_features['src_ip'] = flow_features['src_ip']
                filtered_flow_features['dst_ip'] = flow_features['dst_ip']
                filtered_flow_features['protocol'] = flow_features['protocol']
                if attack_predictions[0] != 'BENIGN':
                    detected_threats += 1

                # You can define your own criteria for priority cases
                if attack_predictions[0] in ['DDoS', 'DoS', 'Brute Force']:
                    priority_cases += 1
                socketio.emit('update_data', {'data': filtered_flow_features}, namespace='/')  # Emit to all client
            socketio.emit('update_stats', {
                'events_analyzed': events_analyzed,
                'detected_threats': detected_threats,
                'priority_cases': priority_cases
            }, namespace='/')
            time.sleep(int(update_interval))

def setup_event_listeners(socketio):
    @socketio.on('connect')
    def handle_connect():
        print('Client connected')

    @socketio.on('disconnect')
    def handle_disconnect():
        print('Client disconnected')

    
    socketio.start_background_task(target=background_task)
    socketio.start_background_task(target=background_alert_task)
