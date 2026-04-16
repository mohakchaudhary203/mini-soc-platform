# Mini SOC Platform

## 📌 Overview
Mini SOC Platform that correlates user login behavior with IP threat intelligence (VirusTotal + local database) to detect and prioritize security incidents using risk scoring.

---

## 🚀 Features
- Detects suspicious login behavior (odd hours, impossible travel)
- Checks IP reputation using:
  - Local threat database
  - VirusTotal API
- Correlates behavior + threat intelligence
- Generates risk scores and final incident verdict
- Saves analysis report to file
- Secure API key handling using environment variables

---

## 🧠 SOC Workflow Simulation
1. Collect login logs  
2. Detect anomalies (time & location)  
3. Analyze IP reputation  
4. Correlate alerts  
5. Generate final risk verdict  

---

## 📁 Project Structure
mini-soc-platform/
│── soc_analyzer.py  
│── logs.csv  
│── threat_db.json  
│── README.md  
│── .gitignore  

---

## 🔐 Security Note
This project uses VirusTotal API.  
API key is stored securely using `.env` file and is not included in this repository.

---

## ▶️ How to Run

```bash
pip install requests python-dotenv
python soc_analyzer.py
