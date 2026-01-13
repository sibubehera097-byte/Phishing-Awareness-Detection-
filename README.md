# 🛡️ Phishing Awareness & Detection System

A cybersecurity web application that helps users detect phishing links and understand online threats using VirusTotal intelligence and URL validation.

This project was built to help individuals, students, and organizations avoid phishing attacks by verifying suspicious links in real time.

---

## 🚀 Features

- 🔍 Check suspicious URLs for phishing and malware
- 🧠 Uses VirusTotal API for real-time threat intelligence
- 🌐 Web-based interface (Flask)
- 📊 Stores scanned URLs and results
- ⚡ Fast and simple to use

---

## 🧑‍💻 Technologies Used

- Python  
- Flask  
- HTML, CSS  
- VirusTotal API  
- SQLite  
- Requests Library  

---

## 📂 Project Structure

Phishing-Awareness-Detection/
│
├── app.py # Main Flask application
├── phishing.db # Database storing scan history
├── templates/ # HTML templates
├── static/ # CSS and static files
└── README.md # Project documentation

yaml

---

## 🔧 How to Run the Project

1️⃣ Clone the repository

git clone https://github.com/sibubehera097-byte/Phishing-Awareness-Detection-.git
cd Phishing-Awareness-Detection-

2️⃣ Install dependencies

#BASH
pip install flask requests validators

3️⃣ Set VirusTotal API key
##Linux / Kali:

#BASH:-
export VIRUSTOTAL_API_KEY="your_api_key_here"

##Windows:
#CMD:-
set VIRUSTOTAL_API_KEY=your_api_key_here

4️⃣ Run the app

#BASH:-
python app.py

#Open in browser:

CPP:-
http://127.0.0.1:5000
