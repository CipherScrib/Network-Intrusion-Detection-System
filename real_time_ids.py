from scapy.all import sniff, IP, TCP, UDP
import numpy as np
import joblib
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from twilio.rest import Client
import os
from dotenv import load_dotenv 

# Load environment variables
load_dotenv()

# Load the trained SVM model
try:
    svm_model = joblib.load("svm_model.pkl")  # Ensure this file exists
    print("✅ SVM Model loaded successfully.")
except FileNotFoundError:
    print("❌ Error: SVM model file 'svm_model.pkl' not found!")
    exit()

# Twilio & Email Configuration (Loaded from .env)
TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")
TO_PHONE_NUMBER = os.getenv("TO_PHONE_NUMBER")
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
TO_EMAIL = os.getenv("TO_EMAIL")

def log_attack(message):
    """Logs detected intrusions to a file with timestamps"""
    try:
        with open("intrusion_log.txt", "a", encoding="utf-8") as log_file:
            log_file.write(message + "\n")
        print(f"✅ Attack logged successfully: {message}")
    except Exception as e:
        print(f"❌ Error logging attack: {e}")

def send_sms_alert(src_ip, dst_ip):
    """ Sends an SMS when an intrusion is detected """
    try:
        client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)
        message_body = f"🚨 Intrusion detected from {src_ip} to {dst_ip}. Immediate action required!"
        message = client.messages.create(
            body=message_body,
            from_=TWILIO_PHONE_NUMBER,
            to=TO_PHONE_NUMBER
        )
        print(f"📱 SMS Alert Sent: {message.sid}")
    except Exception as e:
        print(f"❌ SMS Alert Failed: {e}")

def send_email_alert(src_ip, dst_ip):
    """ Sends an email when an intrusion is detected """
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD or not TO_EMAIL:
        print("❌ Email configuration missing! Check .env file.")
        return

    subject = "🚨 Intrusion Alert - Network Security"
    body = f"Intrusion detected from {src_ip} to {dst_ip}. Immediate action required!"
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = TO_EMAIL

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, TO_EMAIL, msg.as_string())
        server.quit()
        print(f"📧 Email Alert Sent to {TO_EMAIL}")
    except Exception as e:
        print(f"❌ Email Alert Failed: {e}")

def extract_features(packet):
    """Extracts relevant network features from a packet"""
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            packet_size = len(packet)
            ttl = packet[IP].ttl
            
            src_port, dst_port, window_size = 0, 0, 0
            urg_flag, ack_flag, syn_flag, fin_flag = 0, 0, 0, 0
            
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                window_size = packet[TCP].window
                urg_flag = int(packet[TCP].flags & 0x20 != 0)
                ack_flag = int(packet[TCP].flags & 0x10 != 0)
                syn_flag = int(packet[TCP].flags & 0x02 != 0)
                fin_flag = int(packet[TCP].flags & 0x01 != 0)
            
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            print(f"📡 Packet: {src_ip} → {dst_ip} | Protocol: {protocol} | Size: {packet_size}")
            
            features = np.array([
                protocol, packet_size, ttl, src_port, dst_port, window_size,
                urg_flag, ack_flag, syn_flag, fin_flag, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]).reshape(1, -1)
            
            return features, src_ip, dst_ip
    except Exception as e:
        print(f"⚠️ Error extracting features: {e}")
    return None, None, None

def classify_packet(packet):
    """Captures packets and predicts if they are normal or an attack"""
    features, src_ip, dst_ip = extract_features(packet)

    if features is None:
        print("⚠️ Packet skipped (No IP layer or extraction failed)")
        return

    prediction = svm_model.predict(features)[0]  # Predict using SVM
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if prediction == 1:  # Attack detected
        alert_message = f"[ALERT] Intrusion Detected! 🚨 From {src_ip} to {dst_ip}"
        print(alert_message)
        send_email_alert(src_ip, dst_ip)
        send_sms_alert(src_ip, dst_ip)
        log_attack(alert_message)
    else:
        print(f"✅ [{timestamp}] Normal Traffic: {src_ip} → {dst_ip}")

# Start packet sniffing
print("🔍 Starting real-time packet monitoring...")
sniff(prn=classify_packet, store=0)
