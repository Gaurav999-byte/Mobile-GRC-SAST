# Mobile-GRC-SAST

## Governance and Risk Assessment of Mobile Application Using SAST

Mobile-GRC-SAST is a FastAPI-based cybersecurity tool developed for static analysis of Android APK applications. The project performs Governance, Risk Assessment, and Static Application Security Testing (SAST) to identify mobile application vulnerabilities and generate automated security reports.

---

## Features

- APK File Upload and Analysis
- Static Application Security Testing (SAST)
- Android APK Vulnerability Detection
- Governance and Risk Mapping
- Severity Classification (Critical, High, Medium, Low)
- Interactive Dashboard and Charts
- Automated PDF and DOCX Report Generation
- OWASP/GRC-based Risk Analysis

---

## Technologies Used

- Python 3.11
- FastAPI
- Androguard
- HTML/CSS
- Jinja2 Templates
- Matplotlib
- PDFKit
- XHTML2PDF
- Machine Learning Model

---

## Project Workflow

1. User uploads APK file
2. APK is analyzed using static analysis
3. Vulnerabilities are detected
4. Findings are mapped to risk categories
5. Severity summary and charts are generated
6. PDF and DOCX reports are created automatically

---

## Installation

### Clone Repository

```bash
git clone https://github.com/Gaurav999-byte/Mobile-GRC-SAST.git
cd Mobile-GRC-SAST
```

### Create Virtual Environment

```bash
py -3.11 -m venv venv
venv\Scripts\activate
```

### Install Requirements

```bash
pip install -r requirements.txt
```

### Run Project

```bash
python -m uvicorn app.main:app --reload
```

---

## Access Application

Open browser:

```text
http://127.0.0.1:8000
```

---

## Project Structure

```text
app/
 ├── analyzer.py
 ├── predictor.py
 ├── reporter.py
 ├── riskmapper.py
 ├── templates/
 ├── static/
```

---

## Future Enhancements

- Dynamic Malware Analysis
- Cloud Deployment
- Real-time Threat Intelligence
- Advanced ML-based Risk Prediction
- Multi-platform Mobile Support

---

## Author

Gaurav Nagrale

Cybersecurity Student | Software Engineer Intern | Ethical Hacking Enthusiast