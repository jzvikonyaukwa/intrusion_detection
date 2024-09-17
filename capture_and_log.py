import pyshark
import os
import time
from flask_socketio import emit
from extensions import socketio
import logging
from collections import Counter, deque
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib
import json


# Alert types corresponding to CICIDS2018 dataset
alert_types = {
    0: 'Benign', 
    1: 'Bot', 
    2: 'Brute Force', 
    3: 'DDoS', 
    4: 'DoS', 
    5: 'Infiltration', 
    6: 'SQL Injection'
}

def generate_alert(alert_type, description, level="danger", status="Active"):
    alert = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "type": alert_type,
        "description": description,
        "level": level,
        "status": status
    }
    return alert

def save_alert(alert):
    try:
        with open('alerts.json', 'r') as file:
            alerts = json.load(file)
    except FileNotFoundError:
        alerts = []

    alerts.append(alert)

    with open('alerts.json', 'w') as file:
        json.dump(alerts, file, indent=4)

def get_initial_counts():
    global events_analyzed, detected_threats, priority_cases
    try:
        with open('alerts.json', 'r') as file:
            alerts = json.load(file)
    except FileNotFoundError:
        alerts = []

    events_analyzed = len(alerts)
    detected_threats = sum(1 for alert in alerts if alert['type'] != 'Benign')
    priority_cases = sum(1 for alert in alerts if alert['type'] in ['DDoS', 'DoS', 'Brute Force'])
    
    return {
        'events_analyzed': events_analyzed,
        'detected_threats': detected_threats,
        'priority_cases': priority_cases
    }
events_analyzed = 0
detected_threats = 0
priority_cases = 0
attack_type_counter = Counter()
protocol_counter = Counter()







# Configure logging
logging.basicConfig(filename='packet_logs.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Initialize variables for feature calculation
flow_start_time = None
fwd_pkts = 0
bwd_pkts = 0
fwd_pkt_lens = []
bwd_pkt_lens = []
flow_durations = deque(maxlen=1000)
active_times = deque(maxlen=1000)

# Load the pre-trained model and scaler
best_model = joblib.load('models/XGBClassifier_21.pkl')
scaler = joblib.load('models/scaler_21.pkl')

# Map protocol names to numerical values
protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
protocol_map_rev = { 6:'TCP', 17:'UDP',  1:'ICMP'}
# Define signature-based detection rules
def detect_signature_based_attacks(features):
    """
    Detect attacks based on predefined signatures from CICIDS2018 dataset features.
    """
    # Ensure features are correctly mapped to the dataset columns

    # Check for DDoS based on high number of forward packets with UDP protocol
    if features['Tot Fwd Pkts'] > 10000 and features['Protocol'] == protocol_map['UDP']:
        return 'attack', "High number of forward packets with UDP protocol - Possible DDoS"

    # Check for DoS based on high bytes per second with no backward packets
    if features['Flow Byts/s'] > 1000000 and features['TotLen Bwd Pkts'] == 0:
        return 'attack', "High bytes per second with no backward packets - Possible DoS"

    # Check for Brute Force based on high packet length and flow rate
    if features['Bwd Pkt Len Max'] > 500 and features['Flow Pkts/s'] > 100:
        return 'attack', "High packet length and flow rate - Possible Brute Force"

    # Check for Infiltration based on the presence of URG flags
    if features['Fwd URG Flags'] > 0 or features['Bwd URG Flags'] > 0:
        return 'attack', "URG flags detected - Possible Infiltration"

    # Check for SQL Injection based on high traffic on port 80
    if features['Dst Port'] == 80 and features['Flow Byts/s'] > 100000:
        return 'attack', "High traffic on port 80 - Possible SQL Injection"

    # Default to Benign if no signature matches
    return 'Benign', "No signature-based attack detected"
def extract_features(packet, current_time):
    """
        This method extracts features of the dataset from the captured traffic.
    """
    global flow_start_time, fwd_pkts, bwd_pkts, fwd_pkt_lens, bwd_pkt_lens, flow_durations, active_times

    if flow_start_time is None:
        flow_start_time = current_time

    flow_duration = (current_time - flow_start_time) * 1000000  # in microseconds
    flow_durations.append(flow_duration)

    if not hasattr(packet, 'ip'):
        return None  # Skip packets without IP layer

    src_ip = packet.ip.src
    dst_port = int(packet[packet.transport_layer].dstport) if hasattr(packet[packet.transport_layer], 'dstport') else 0
    protocol = packet.transport_layer
    protocol_num = protocol_map.get(protocol, 0)

    dst_ip = packet.ip.dst
    if src_ip == 'source_ip':  # Replace 'source_ip' with the actual source IP
        fwd_pkts += 1
        fwd_pkt_lens.append(len(packet))
    else:
        bwd_pkts += 1
        bwd_pkt_lens.append(len(packet))

    fwd_pkt_len_avg = float(np.mean(fwd_pkt_lens)) if fwd_pkt_lens else 0
    fwd_pkt_len_std = float(np.std(fwd_pkt_lens)) if fwd_pkt_lens else 0
    fwd_pkt_len_min = int(np.min(fwd_pkt_lens)) if fwd_pkt_lens else 0
    fwd_pkt_len_max = int(np.max(fwd_pkt_lens)) if fwd_pkt_lens else 0

    bwd_pkt_len_avg = float(np.mean(bwd_pkt_lens)) if bwd_pkt_lens else 0
    bwd_pkt_len_std = float(np.std(bwd_pkt_lens)) if bwd_pkt_lens else 0
    bwd_pkt_len_min = int(np.min(bwd_pkt_lens)) if bwd_pkt_lens else 0
    bwd_pkt_len_max = int(np.max(bwd_pkt_lens)) if bwd_pkt_lens else 0

    pkt_len_avg = float(np.mean(fwd_pkt_lens + bwd_pkt_lens)) if fwd_pkt_lens + bwd_pkt_lens else 0
    pkt_len_var = float(np.var(fwd_pkt_lens + bwd_pkt_lens)) if fwd_pkt_lens + bwd_pkt_lens else 0
    pkt_len_std = float(np.std(fwd_pkt_lens + bwd_pkt_lens)) if fwd_pkt_lens + bwd_pkt_lens else 0
    pkt_len_min = int(np.min(fwd_pkt_lens + bwd_pkt_lens)) if fwd_pkt_lens + bwd_pkt_lens else 0
    pkt_len_max = int(np.max(fwd_pkt_lens + bwd_pkt_lens)) if fwd_pkt_lens + bwd_pkt_lens else 0

    total_time = current_time - (active_times[0] if active_times else current_time)
    fwd_pkts_s = float(fwd_pkts / total_time) if total_time > 0 else 0
    bwd_pkts_s = float(bwd_pkts / total_time) if total_time > 0 else 0

    tot_len_fwd_pkts = sum(fwd_pkt_lens)
    tot_len_bwd_pkts = sum(bwd_pkt_lens)

    flow_byts_s = float((tot_len_fwd_pkts + tot_len_bwd_pkts) / total_time) if total_time > 0 else 0
    flow_pkts_s = float((fwd_pkts + bwd_pkts) / total_time) if total_time > 0 else 0

    fwd_iat_tot = float(sum(np.diff(fwd_pkt_lens))) if len(fwd_pkt_lens) > 1 else 0
    fwd_iat_mean = float(np.mean(np.diff(fwd_pkt_lens))) if len(fwd_pkt_lens) > 1 else 0
    fwd_iat_std = float(np.std(np.diff(fwd_pkt_lens))) if len(fwd_pkt_lens) > 1 else 0
    fwd_iat_max = float(np.max(np.diff(fwd_pkt_lens))) if len(fwd_pkt_lens) > 1 else 0
    fwd_iat_min = float(np.min(np.diff(fwd_pkt_lens))) if len(fwd_pkt_lens) > 1 else 0

    bwd_iat_tot = float(sum(np.diff(bwd_pkt_lens))) if len(bwd_pkt_lens) > 1 else 0
    bwd_iat_mean = float(np.mean(np.diff(bwd_pkt_lens))) if len(bwd_pkt_lens) > 1 else 0
    bwd_iat_std = float(np.std(np.diff(bwd_pkt_lens))) if len(bwd_pkt_lens) > 1 else 0
    bwd_iat_max = float(np.max(np.diff(bwd_pkt_lens))) if len(bwd_pkt_lens) > 1 else 0
    bwd_iat_min = float(np.min(np.diff(bwd_pkt_lens))) if len(bwd_pkt_lens) > 1 else 0

    active_mean = float(np.mean(active_times)) if active_times else 0
    active_std = float(np.std(active_times)) if active_times else 0
    active_max = float(np.max(active_times)) if active_times else 0
    active_min = float(np.min(active_times)) if active_times else 0

    idle_mean = float(np.mean([flow_duration - active_mean])) if flow_duration and active_mean else 0
    idle_std = float(np.std([flow_duration - active_mean])) if flow_duration and active_mean else 0
    idle_max = float(max([flow_duration - active_mean])) if flow_duration and active_mean else 0
    idle_min = float(min([flow_duration - active_mean])) if flow_duration and active_mean else 0

    def calculate_flag_count(flag):
        return sum(1 for pkt in fwd_pkt_lens if flag in str(pkt)) + sum(1 for pkt in bwd_pkt_lens if flag in str(pkt))

    fin_flag_cnt = calculate_flag_count('FIN')
    syn_flag_cnt = calculate_flag_count('SYN')
    rst_flag_cnt = calculate_flag_count('RST')
    psh_flag_cnt = calculate_flag_count('PSH')
    ack_flag_cnt = calculate_flag_count('ACK')
    urg_flag_cnt = calculate_flag_count('URG')
    cwe_flag_count = calculate_flag_count('CWE')
    ece_flag_cnt = calculate_flag_count('ECE')

    fwd_psh_flags = calculate_flag_count('PSH')
    bwd_psh_flags = calculate_flag_count('PSH')
    fwd_urg_flags = calculate_flag_count('URG')
    bwd_urg_flags = calculate_flag_count('URG')

    
    return {
        "Src IP": src_ip,
        "Dst IP": dst_ip,
        "Dst Port": dst_port,
        "Protocol": protocol_num,
        "Timestamp": current_time,
        "Flow Duration": flow_duration,
        "Tot Fwd Pkts": fwd_pkts,
        "Tot Bwd Pkts": bwd_pkts,
        "TotLen Fwd Pkts": tot_len_fwd_pkts,
        "TotLen Bwd Pkts": tot_len_bwd_pkts,
        "Fwd Pkt Len Max": fwd_pkt_len_max,
        "Fwd Pkt Len Min": fwd_pkt_len_min,
        "Fwd Pkt Len Mean": fwd_pkt_len_avg,
        "Fwd Pkt Len Std": fwd_pkt_len_std,
        "Bwd Pkt Len Max": bwd_pkt_len_max,
        "Bwd Pkt Len Min": bwd_pkt_len_min,
        "Bwd Pkt Len Mean": bwd_pkt_len_avg,
        "Bwd Pkt Len Std": bwd_pkt_len_std,
        "Flow Byts/s": flow_byts_s,
        "Flow Pkts/s": flow_pkts_s,
        "Flow IAT Mean": float(np.mean(flow_durations)) if flow_durations else 0,
        "Flow IAT Std": float(np.std(flow_durations)) if flow_durations else 0,
        "Flow IAT Max": float(np.max(flow_durations)) if flow_durations else 0,
        "Flow IAT Min": float(np.min(flow_durations)) if flow_durations else 0,
        "Fwd IAT Tot": fwd_iat_tot,
        "Fwd IAT Mean": fwd_iat_mean,
        "Fwd IAT Std": fwd_iat_std,
        "Fwd IAT Max": fwd_iat_max,
        "Fwd IAT Min": fwd_iat_min,
        "Bwd IAT Tot": bwd_iat_tot,
        "Bwd IAT Mean": bwd_iat_mean,
        "Bwd IAT Std": bwd_iat_std,
        "Bwd IAT Max": bwd_iat_max,
        "Bwd IAT Min": bwd_iat_min,
        "Fwd PSH Flags": fwd_psh_flags,
        "Bwd PSH Flags": bwd_psh_flags,
        "Fwd URG Flags": fwd_urg_flags,
        "Bwd URG Flags": bwd_urg_flags,
        "Fwd Header Len": len(packet[protocol]) if protocol and hasattr(packet, protocol) and not isinstance(packet[protocol], pyshark.packet.layers.json_layer.JsonLayer) else 0,
        "Bwd Header Len": len(packet[protocol]) if protocol and hasattr(packet, protocol) and not isinstance(packet[protocol], pyshark.packet.layers.json_layer.JsonLayer) else 0,
        "Fwd Pkts/s": fwd_pkts_s,
        "Bwd Pkts/s": bwd_pkts_s,
        "Pkt Len Min": pkt_len_min,
        "Pkt Len Max": pkt_len_max,
        "Pkt Len Mean": pkt_len_avg,
        "Pkt Len Std": pkt_len_std,
        "Pkt Len Var": pkt_len_var,
        "FIN Flag Cnt": fin_flag_cnt,
        "SYN Flag Cnt": syn_flag_cnt,
        "RST Flag Cnt": rst_flag_cnt,
        "PSH Flag Cnt": psh_flag_cnt,
        "ACK Flag Cnt": ack_flag_cnt,
        "URG Flag Cnt": urg_flag_cnt,
        "CWE Flag Count": cwe_flag_count,
        "ECE Flag Cnt": ece_flag_cnt,
        "Down/Up Ratio": float(fwd_pkts / bwd_pkts) if bwd_pkts > 0 else 0,
        "Pkt Size Avg": pkt_len_avg,
        "Fwd Seg Size Avg": fwd_pkt_len_avg,
        "Bwd Seg Size Avg": bwd_pkt_len_avg,
        "Fwd Byts/b Avg": float(tot_len_fwd_pkts / fwd_pkts) if fwd_pkts > 0 else 0,
        "Fwd Pkts/b Avg": float(fwd_pkts / len(fwd_pkt_lens)) if fwd_pkt_lens else 0,
        "Fwd Blk Rate Avg": float(tot_len_fwd_pkts / len(fwd_pkt_lens)) if fwd_pkt_lens else 0,
        "Bwd Byts/b Avg": float(tot_len_bwd_pkts / bwd_pkts) if bwd_pkts > 0 else 0,
        "Bwd Pkts/b Avg": float(bwd_pkts / len(bwd_pkt_lens)) if bwd_pkt_lens else 0,
        "Bwd Blk Rate Avg": float(tot_len_bwd_pkts / len(bwd_pkt_lens)) if bwd_pkt_lens else 0,
        "Subflow Fwd Pkts": fwd_pkts,
        "Subflow Fwd Byts": tot_len_fwd_pkts,
        "Subflow Bwd Pkts": bwd_pkts,
        "Subflow Bwd Byts": tot_len_bwd_pkts,
        "Init Fwd Win Byts": 0,  # Placeholder, replace with actual calculation if available
        "Init Bwd Win Byts": 0,  # Placeholder, replace with actual calculation if available
        "Fwd Act Data Pkts": fwd_pkts,  # Assuming all forward packets are active data packets
        "Fwd Seg Size Min": fwd_pkt_len_min,
        "Active Mean": active_mean,
        "Active Std": active_std,
        "Active Max": active_max,
        "Active Min": active_min,
        "Idle Mean": idle_mean,
        "Idle Std": idle_std,
        "Idle Max": idle_max,
        "Idle Min": idle_min
    }

def capture_packets(interface='eth0'):
    X = [
        'ACK Flag Cnt', 'Bwd Pkt Len Max', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Min', 'Bwd Pkt Len Std',
        'Bwd Seg Size Avg', 'Dst Port', 'Fwd Pkt Len Max', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Min',
        'Fwd Pkt Len Std', 'Fwd Seg Size Avg', 'Fwd Seg Size Min', 'Init Bwd Win Byts', 'Init Fwd Win Byts',
        'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Min', 'Pkt Len Std', 'Pkt Size Avg', 'Protocol'
    ]
    
    attack_mapping = {
        0: 'Benign', 1: 'Bot', 2: 'Brute Force', 3: 'DDoS', 4: 'DoS', 5: 'Infiltration', 6: 'SQL Injection'
    }
    
    def packet_callback(packet):
        global events_analyzed, detected_threats, priority_cases
        update_interval = 2
        
        try:
            current_time = packet.sniff_time.timestamp()
            features = extract_features(packet, current_time)
            events_analyzed += 1
            if features:
                # Detect signature-based attacks
                alert_type, description = detect_signature_based_attacks(features)
                if alert_type != 'Benign':
                    print('ALERT ----------------> ', alert_type, description)
                    alert = generate_alert(alert_type, description,  level= "danger" if alert_type in ['DDoS', 'DoS', 'Brute Force', 'attack'] 
                                   else("info" if alert_type in ['Benign'] else "warning"))
                    print('ALERT ----------------> ', alert)
                    save_alert(alert)
                    socketio.emit('update_alerts', alert,  namespace='/')

                X_real = pd.DataFrame([features])
                X_real = X_real.reindex(columns=X, fill_value=0)
                X_real_scaled = scaler.transform(X_real) # Normalise the capture features
                y_real_pred = best_model.predict(X_real_scaled) # predict
                # attack_prediction = 'BENIGN' if y_real_pred[0] == 0 else 'ATTACK'
                attack_predictions = [attack_mapping[label] for label in y_real_pred] #mapping the predicted encode values to label names
                attack_prediction=attack_predictions[0]
                
                #Benign is the Normal traffic 
                if attack_predictions[0] != 'Benign': #Check if the traffic is not normal
                    detected_threats += 1
                    attack_type_counter[attack_predictions[0]] += 1
                    protocol_counter[protocol_map_rev[features['Protocol']]] += 1
                
                if attack_predictions[0] in ['DDoS', 'DoS', 'Brute Force']:
                    priority_cases += 1
                time.sleep(int(update_interval))
                alert = generate_alert(
                    alert_type=attack_prediction,
                    description=f"Detected {attack_prediction} from {features['Src IP']} to {features['Dst IP']} on port {features['Dst Port']}",
                    level= "danger" if attack_prediction in ['DDoS', 'DoS', 'Brute Force', 'attack'] 
                                   else("info" if attack_prediction in ['Benign'] else "warning")
                )  
                save_alert(alert)
                socketio.emit('update_alerts', alert, namespace='/')

                raw_packet = packet.get_raw_packet()
                raw_packet_str = raw_packet.decode(errors='ignore')
                socketio.emit('update_stats', {
                    'events_analyzed': events_analyzed,
                    'detected_threats': detected_threats,
                    'priority_cases': priority_cases,
                    'attack_type_counts': list(attack_type_counter.values()),
                    'protocol_counts': list(protocol_counter.values())
                }, namespace='/')
                
                socketio.emit('update_data', {
                    'src_ip': features['Src IP'],
                    'dst_ip': features['Dst IP'],
                    'protocol': protocol_map_rev[features['Protocol']],
                    'dst_port': features['Dst Port'],
                    'attack_type': attack_prediction,
                    'timestamp': features['Timestamp'],
                    'flow_duration': features['Flow Duration'],
                    'alert_level':alert['level']
                }, namespace='/')
                
                if 'Scapy-Generated' in raw_packet_str:
                    logging.info(f"ATTACK FROM SCAPY: {attack_prediction} - Features: {features}")
                    print(f"ATTACK FROM SCAPY: {attack_prediction}")
                else:
                    logging.info(f"REGULAR: {raw_packet_str}")
                    print(f"REGULAR: {raw_packet_str} attack -> {attack_prediction}")
                
                
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
            print(f"Error processing packet: {e}")

    cap = pyshark.LiveCapture(interface=interface, use_json=True, include_raw=True)
    cap.apply_on_packets(packet_callback)

# if __name__ == "__main__":
#     interface = os.getenv('INTERFACE', 'eth0')
#     capture_packets(interface)


def background_task():
   
    interface = os.getenv('INTERFACE', 'eth0')

    while True:
        capture_packets(interface)
        
def setup_event_listeners(socketio):
    @socketio.on('connect')
    def handle_connect():
        print('Client connected')
        initial_counts = get_initial_counts()
        emit('update_stats', initial_counts, namespace='/')


    @socketio.on('disconnect')
    def handle_disconnect():
        print('Client disconnected')
    
    socketio.start_background_task(target=background_task)