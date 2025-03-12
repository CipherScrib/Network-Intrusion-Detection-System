🛡️Network Intrusion Detection System (NIDS)

📌 Overview
A real-time Network Intrusion Detection System (NIDS) that monitors network traffic, detects malicious activity using machine learning, and sends automated alerts via email & SMS.

🚀 Features
✅ Real-Time Network Monitoring (Scapy) ✅ ML-Based Detection (SVM, KNN on KDDCup'99) ✅ Automated Alerts (SMTP & Twilio API) ✅ Intrusion Logging ✅ 97% Detection Accuracy

🛠️ Tech Stack
Python, Scikit-Learn, Pandas, NumPy

Scapy (Packet Sniffing)

SMTP & Twilio API (Alerts)

File-based Logging

📂 Project Structure
📁 NIDS-Project
   ├── IDS.py  # ML Model (SVM, KNN)
   ├── knn.py  # KNN Algorithm
   ├── real_time_ids.py  # Live Monitoring & Alerts
   ├── svm_model.pkl  # Trained Model
   ├── README.md  # Documentation
   
📖 How It Works
1️⃣ Train ML Model: python IDS.py 2️⃣ Start Detection: python real_time_ids.py 3️⃣ Receive Alerts (Email & SMS)

📩 Installation
pip install numpy pandas scikit-learn scapy twilio
Configure Email & Twilio API in real_time_ids.py.

📌 Future Enhancements
🔹 IP Blocking 🔹 Database Logging 🔹 Live Dashboard

👨‍💻 Author
👩‍💻 Sneha Rajurikar – Cybersecurity & Ethical Hacking 🔐🤖
📧 Email: rajurikarsneha@gmail.com
📌 LinkedIn: linkedin.com/in/sneha-rajurikar/

📜 License
Open-source under MIT License.
