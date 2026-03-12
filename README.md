# 🎣 Phishing URL Detection System

![Python](https://img.shields.io/badge/Python-3.11-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3.3-lightgrey.svg)
![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.7.2-orange.svg)
![Deployment](https://img.shields.io/badge/Deployed-Hugging_Face-yellow.svg)

## 📌 Overview
The Phishing URL Detection System is a machine learning-powered web application designed to proactively identify and classify malicious web links. Built with a focus on threat intelligence and rapid Indicator of Compromise (IOC) analysis, this tool analyzes the lexical features of a URL to predict whether it is legitimate or a phishing attempt.

**[Try the Live Application Here](https://huggingface.co/spaces/Arya3191/phishing-url-system)**

## 🚀 Features
* **Real-Time Classification:** Instantly evaluates URLs using a pre-trained machine learning model.
* **Feature Extraction:** Automatically parses URLs to extract critical structural data (domain length, special characters, suspicious keywords) without needing to visit the potentially malicious site.
* **Containerized Deployment:** Packaged via Docker and deployed on Hugging Face Spaces for high availability and scalable memory management.
* **RESTful Architecture:** Built on Flask, easily extensible for API integrations.

## 🛠️ Technology Stack
* **Backend:** Python, Flask, Gunicorn
* **Machine Learning:** Scikit-Learn, Pandas, NumPy, Joblib
* **Data Extraction:** BeautifulSoup4, Python-Whois, Requests
* **Deployment:** Docker, Hugging Face Spaces, Git LFS (Large File Storage)

## 💻 Local Installation & Setup
To run this project locally for development or testing:

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/ARYANSINGHas22/Phishing-url-system.git](https://github.com/ARYANSINGHas22/Phishing-url-system.git)
   cd Phishing-url-system
