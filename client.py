import joblib
import pandas as pd
import requests
import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from sklearn.preprocessing import StandardScaler

# Load all models and preprocessing tools
models = {
    'Logistic Regression': joblib.load('Logistic_Regression.pkl'),
    'Neural Network': joblib.load('Neural_Network.pkl'),
    'Naive Bayes': joblib.load('Naive_Bayes.pkl'),
    'Decision Tree': joblib.load('Decision_Tree.pkl'),
    'Random Forest': joblib.load('Random_Forest.pkl')
}

scaler = joblib.load('scaler.pkl')
label_encoders = joblib.load('label_encoders.pkl')

# Function to preprocess packet data
def preprocess_packet(packet_data):
    packet_df = pd.DataFrame([packet_data])

    # Encode categorical features
    for column, le in label_encoders.items():
        if column in packet_df:
            try:
                packet_df[column] = le.transform(packet_df[column])
            except ValueError:
                packet_df[column] = 0  # Default for unseen labels

    # Scale numerical data
    packet_scaled = scaler.transform(packet_df)
    return packet_scaled

# Function to send JSON response to server
def send_log_to_server(json_payload):
    try:
        # Updated URL to match the correct route in the Flask application
        response = requests.post("http://localhost:5000/log_prediction", json=json_payload)
        #print(f"Sent to server: {json_payload}")
    except Exception as e:
        print(f"Failed to send log to server: {e}")

# Function to build JSON response
def build_json_response(packet_data, results):
    return {
        "models": results,
        "packet_details": packet_data,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }

# Function to predict and log intrusion detection results for all models
def predict_and_update(packet_data):
    # Preprocess packet data
    processed_data = preprocess_packet(packet_data)
    
    # Store results from each model
    results = {}

    # Predict with each model
    for model_name, model in models.items():
        prediction = model.predict(processed_data)
        intrusion_status = "Intrusion Detected" if prediction[0] == 1 else "No Intrusion"
        results[model_name] = {
            "prediction": int(prediction[0]),
            "intrusion_status": intrusion_status
        }
    
    # Build JSON payload with results from all models
    json_payload = build_json_response(packet_data, results)
    
    # Send the JSON response to the server
    send_log_to_server(json_payload)
    
    #print("Results:", results)
    return results

# Function to extract features from each packet
def process_packet(packet):
    # Extract common features for intrusion detection
    packet_data = {
        'Source Port': packet.sport if hasattr(packet, 'sport') else 0,
        'Destination Port': packet.dport if hasattr(packet, 'dport') else 0,
        'Protocol': packet.proto if hasattr(packet, 'proto') else 'N/A',
        'Packet Length': len(packet),
        'TTL': packet.ttl if hasattr(packet, 'ttl') else 0,
        'Flags': str(packet.flags) if hasattr(packet, 'flags') else 'N/A',
        'Flow Duration': 0,  # Placeholder
        'Packet Count': 1,   # Single packet count for real-time capture
        'Average Packet Size': len(packet),  # Same as length for single packet
        'Payload Size': len(packet.payload) if packet.payload else 0,
        'Window Size': packet.window if hasattr(packet, 'window') else 0,
        'Urgent Pointer': packet.urgptr if hasattr(packet, 'urgptr') else 0
    }

    # Convert flags and protocol to categorical codes, handling unseen values
    if isinstance(packet_data['Protocol'], str):
        try:
            packet_data['Protocol'] = label_encoders['Protocol'].transform([packet_data['Protocol']])[0]
        except ValueError:
            packet_data['Protocol'] = 0  # Default for unseen Protocol

    if isinstance(packet_data['Flags'], str):
        try:
            packet_data['Flags'] = label_encoders['Flags'].transform([packet_data['Flags']])[0]
        except ValueError:
            packet_data['Flags'] = 0  # Default for unseen Flags

    # Predict and log intrusion detection result
    predict_and_update(packet_data)

# Capture packets and process each one with process_packet function
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(filter="ip", prn=process_packet, store=0)
