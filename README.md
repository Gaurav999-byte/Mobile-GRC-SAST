# ML-Enhanced Mobile Security Governance Platform

## ML-Enhanced Governance and Risk Assessment of Mobile Applications Using SAST

ML-Enhanced Mobile Security Governance Platform is a FastAPI-based cybersecurity and governance assessment system developed for automated Static Application Security Testing (SAST) of Android APK applications. The platform performs vulnerability detection, ML-assisted risk prediction, governance mapping, and automated compliance reporting for mobile applications.

---

# Project Overview

The project focuses on identifying security vulnerabilities in Android APK files using Static Application Security Testing (SAST) techniques. The system analyzes uploaded APK files, detects common security weaknesses, classifies risks using Machine Learning-assisted prediction, and maps findings to governance and compliance frameworks such as:

- ISO 27001
- GDPR
- OWASP MASVS / MSTG

The platform also generates automated HTML, PDF, and DOCX security assessment reports with severity visualization and compliance recommendations.

---

# Features

- Android APK Upload and Analysis
- Static Application Security Testing (SAST)
- ML-Based Risk Prediction
- Vulnerability Severity Classification
- Governance and Compliance Mapping
- ISO 27001 / GDPR / OWASP Mapping
- Interactive Security Dashboard
- Severity Distribution Visualization
- Automated PDF & DOCX Report Generation
- Modern Responsive UI/UX
- ML Confidence Scoring
- Risk Assessment Reporting

---

# Technologies Used

| Component | Technology |
|---|---|
| Programming Language | Python 3.11 |
| Backend Framework | FastAPI |
| Static Analysis | Androguard |
| Machine Learning | Scikit-learn |
| ML Model Handling | Joblib |
| Frontend | HTML5, CSS3, JavaScript |
| Templates | Jinja2 |
| Visualization | Matplotlib |
| PDF Generation | XHTML2PDF |
| DOCX Generation | python-docx |
| API Server | Uvicorn |
| Version Control | Git & GitHub |

---

# Project Workflow

1. User uploads Android APK file
2. APK undergoes static security analysis
3. Vulnerabilities and insecure configurations are detected
4. Findings are mapped to governance frameworks
5. ML model predicts risk severity and confidence score
6. Severity charts and summaries are generated
7. HTML, PDF, and DOCX reports are created automatically

---

# Installation

## Clone Repository

```bash
git clone https://github.com/Gaurav999-byte/Mobile-GRC-SAST.git
cd Mobile-GRC-SAST
```

---

## Create Virtual Environment

```bash
py -3.11 -m venv venv
```

---

## Activate Virtual Environment

### Windows

```bash
venv\Scripts\activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Run Project

```bash
python run.py
```

---

# Access Application

Open browser:

```text
http://127.0.0.1:8000
```

---

# Project Structure

```text
Mobile-GRC-SAST/
│
├── app/
│   ├── analyzer.py
│   ├── predictor.py
│   ├── reporter.py
│   ├── riskmapper.py
│   ├── main.py
│   ├── rules.json
│   │
│   ├── templates/
│   │   ├── index.html
│   │   ├── report.html
│   │   ├── report_preview.html
│   │   └── report_pdf.html
│   │
│   └── static/
│       └── css/
│
├── outputs/
├── uploads/
├── rf_model.pkl
├── vectorizer.pkl
├── requirements.txt
├── run.py
└── README.md
```

---

# Machine Learning Integration

The project integrates a Machine Learning-assisted risk prediction system using the Random Forest algorithm. The ML module predicts:

- Vulnerability Severity
- Risk Classification
- Confidence Score

This enhances traditional SAST analysis by introducing intelligent risk evaluation and automated severity assessment.

---

# Future Enhancements

- Dynamic Malware Analysis
- Real-Time Threat Intelligence
- Cloud Deployment
- Deep APK Reverse Engineering
- Advanced ML Model Training
- CVSS Score Integration
- Scan History Management
- Multi-Platform Mobile Support
- Role-Based Access Control

---

# Author

## Gaurav Nagrale

Cybersecurity Student    
Ethical Hacking & Security Research Enthusiast

---

# Disclaimer

This project is developed strictly for educational, academic, and cybersecurity research purposes only.
