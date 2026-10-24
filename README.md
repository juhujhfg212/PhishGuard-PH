# 🛡️ PhishGuard PH

### Triple-Layer Offline Phishing URL Detector for Filipinos

**CpE Elective 1 – Applied Machine Learning and Software Development**
**1st Semester, A.Y. 2026-2027**

---

## 📌 Overview

PhishGuard PH is an offline phishing URL detection tool designed to protect Filipino internet users from online scams targeting GCash, Maya, BDO, BPI, Shopee, and other popular platforms. The application uses a **triple-layer detection system** combining Machine Learning, Rule-Based Analysis, and Clone/Homoglyph Detection to identify malicious URLs without requiring an internet connection.

---

## 🎯 Problem Statement

The Philippines is one of the most targeted countries in Southeast Asia for phishing attacks. With the widespread adoption of GCash, Maya, and online banking, Filipino users are frequently exposed to fraudulent links via SMS, email, and social media. Many users lack the technical knowledge to identify malicious URLs, leading to financial loss and data theft. PhishGuard PH addresses this by providing a simple, offline tool that instantly evaluates URL safety.

---

## 🧠 Detection Architecture

### Layer 1: AI Model (Machine Learning)
- **Algorithm:** Random Forest Classifier
- **Training Data:** 11,055 URLs from UCI Machine Learning Repository
- **Features:** 14 URL-based characteristics
- **Accuracy:** 91.04%
- **Baseline Comparison:** Logistic Regression (89.51%)

### Layer 2: Rule Engine
- Checks for 14+ known phishing patterns
- Detects URL shorteners, suspicious keywords, missing HTTPS
- Identifies brand impersonation and redirect attacks
- Threshold-based alerting (3+ flags = danger)

### Layer 3: Clone/Homoglyph Detector
- Character substitution detection (0→o, 1→l, 4→a, rn→m)
- Typo-squatting similarity analysis
- Brand spoofing detection (17 PH/Global brands)
- @ split attack detection (e.g., payp@l.com)

---

## 📊 Dataset

| Detail | Value |
|--------|-------|
| **Source** | UCI Machine Learning Repository (ID: 327) |
| **Records** | 11,055 original URLs |
| **Features** | 30 total (14 URL-extractable used) |
| **Classes** | Phishing (4,898) / Legitimate (6,157) |
| **Missing Values** | 0 |
| **Split** | 80% Training / 20% Testing |

---

## 📈 Model Performance

| Metric | Logistic Regression | Random Forest |
|--------|-------------------|---------------|
| **Accuracy** | 89.51% | **91.04%** |
| **Precision** | 88.22% | **89.95%** |
| **Recall** | 93.66% | **94.48%** |
| **F1-Score** | 90.86% | **92.16%** |

---

## 🏢 Protected Brands (17)

GCash, Maya, BDO, BPI, Metrobank, Shopee, Lazada, Grab, Globe, Smart, PayPal, Facebook, Google, Netflix, PhilHealth, SSS, Pag-IBIG

---

## 💻 Tech Stack

| Component | Technology |
|-----------|-----------|
| **Language** | Python 3.11 |
| **ML Library** | scikit-learn 1.9.0 |
| **Data Processing** | pandas 3.0.5, numpy 2.4.6 |
| **App Framework** | Streamlit 1.66.1 |
| **Model Storage** | joblib 1.5.3 |
| **Dataset Source** | ucimlrepo 0.0.7 |

---

## 🚀 Installation and Setup

### Prerequisites
- Windows 10/11
- Python 3.11+
- PowerShell or Command Prompt

### Step 1: Clone the Repository
```bash
git clone https://github.com/juhujhfg212/PhishGuard-PH.git
cd PhishGuard-PH