# Mini SOC Platform

## 📌 Overview
A Python-based Mini SOC Platform that correlates user login behavior with IP threat intelligence to detect security incidents.

## 🚀 Features
- Login anomaly detection
- IP reputation (local + VirusTotal)
- Risk scoring system
- Final threat verdict
- Report generation

## 📁 Project Structure
mini-soc-platform/
│── soc_analyzer.py  
│── logs.csv  
│── threat_db.json  
│── README.md
│── .gitignore 

## 🔐 Security Note
API key is stored securely using environment variables (.env file) and is not included in this repository.

## ▶️ How to Run
```bash
pip install requests python-dotenv
python soc_analyzer.py