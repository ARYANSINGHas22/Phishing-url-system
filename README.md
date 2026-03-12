# 🎣 Phishing URL Detection System

![Python](https://img.shields.io/badge/Python-3.11-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3.3-lightgrey.svg)
![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.7.2-orange.svg)
![Deployment](https://img.shields.io/badge/Deployed-Hugging_Face-yellow.svg)

---

## 📌 Overview

The **Phishing URL Detection System** is a machine learning-powered web application designed to proactively identify and classify malicious web links. Built with a focus on **threat intelligence** and rapid **Indicator of Compromise (IOC)** analysis, this tool analyzes the lexical features of a URL to predict whether it is legitimate or a phishing attempt.

👉 **Try the Live Application:**  
[![Try it now](https://huggingface.co/spaces/Arya3191/phishing-url-system)](https://huggingface.co/spaces/Arya3191/phishing-url-system)

---

## 🚀 Features

- **Real-Time Classification:** Instantly evaluates URLs using a pre-trained machine learning model.
- **Feature Extraction:** Automatically parses URLs to extract critical structural data (domain length, special characters, suspicious keywords) without visiting the potentially malicious site.
- **Containerized Deployment:** Packaged via Docker and deployed on Hugging Face Spaces for scalable deployment.
- **RESTful Architecture:** Built with Flask and easily extendable for API integrations.

---

## 🛠️ Technology Stack

**Backend**
- Python
- Flask
- Gunicorn

**Machine Learning**
- Scikit-Learn
- Pandas
- NumPy
- Joblib

**Data Extraction**
- BeautifulSoup4
- Python-Whois
- Requests

**Deployment**
- Docker
- Hugging Face Spaces
- Git LFS (Large File Storage)

---

## 💻 Local Installation & Setup



```bash
1️⃣ Clone the repository
git clone https://github.com/ARYANSINGHas22/Phishing-url-system.git
cd Phishing-url-system

2️⃣ Create a virtual environment
python -m venv venv
# Activate it:
# Windows: venv\Scripts\activate
# Linux/Mac: source venv/bin/activate

3️⃣ Install dependencies
pip install -r requirements.txt

4️⃣ Run the application
gunicorn app:app

'''

👨‍💻 Author
Aryan Singh
Aspiring SOC Analyst & Security Researcher

🔗[![LinkedIn Profile]https://www.linkedin.com/in/aryan-singh-a8456528a/](https://www.linkedin.com/in/aryan-singh-a8456528a/)
