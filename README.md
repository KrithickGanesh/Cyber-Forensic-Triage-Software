# 🛡️ Cyber Forensic Triage Software

**AI-powered portable forensic triage tool for non-technical law enforcement.**

> Process digital evidence 75% faster. Zero training required. Court-ready reports in minutes.

Built for **Cyber Hackathon v4.0** & **AMD Slingshot**

---

## The Problem

Digital forensics faces a crisis: **9–12 month case backlogs**, 75% of investigators report resource constraints, and each case takes **45+ hours**. Existing tools like EnCase and Cyber Triage are expensive ($3,000–$35,000), require extensive training, and lack on-scene AI automation.

## The Solution

A portable, AI-powered triage tool that any police officer can use on-scene — plug in a USB drive, click scan, get a court-ready report. No forensics degree required.

---

## Features

| Feature | Description |
|---------|-------------|
| 🔍 **Automated Scanning** | Recursive file system scanner with metadata collection |
| 🔒 **SHA-256 Hashing** | Tamper-evident integrity verification for every file |
| 🤖 **AI Analysis** | Google Gemini-powered forensic file assessment |
| 🚦 **RAG Classification** | Red-Amber-Green priority system with confidence scores |
| 📊 **Forensic Timeline** | Chronological event reconstruction from file timestamps |
| 📄 **Court-Ready PDF Reports** | Professional reports with chain-of-custody documentation |
| 🦠 **VirusTotal Integration** | Malware hash lookup against known threat databases |
| 🔎 **Artifact Extraction** | Browser history, registry hives, and log file detection |

---

## RAG Threat Classification

Files are scored (0–100) based on forensic signals and classified:

| Score | Level | Meaning |
|-------|-------|---------|
| 50–100 | 🔴 **RED** | High priority — immediate attention |
| 20–49 | 🟡 **AMBER** | Flagged for further review |
| 0–19 | 🟢 **GREEN** | No immediate concerns |

**Signals scored:** file extension risk, suspicious filenames (password, keylog, exploit...), hidden files, suspicious paths (temp, recycle bin, .tor), file size anomalies, extension mismatches, and VirusTotal results.

---

## Tech Stack

- **Backend:** Python + Flask
- **Database:** SQLite (portable, no server needed)
- **Frontend:** HTML + Vanilla CSS + JavaScript
- **AI:** Google Gemini API
- **Reports:** ReportLab (PDF generation)
- **Hashing:** hashlib (SHA-256 + MD5)
- **Threat Intel:** VirusTotal API

---

## Quick Start

### 1. Clone & Setup
```bash
git clone https://github.com/KrithickGanesh/Cyber-Forensic-Triage-Software.git
cd Cyber-Forensic-Triage-Software
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

### 2. Configure API Keys
Create a `.env` file:
```
VIRUSTOTAL_API_KEY=your_key_here
GEMINI_API_KEY=your_key_here
FLASK_SECRET_KEY=your_secret_key
```

### 3. Run
```bash
python app.py
```
Open **http://127.0.0.1:5000** in your browser.

---

## How It Works

```
Create Case → Point to Evidence → Start Scan → View Results → Export PDF
```

**5-Step Scan Pipeline:**
1. **Scan** — Recursively walks target directory, collects file metadata
2. **Hash** — Computes SHA-256 for every file (integrity verification)
3. **Analyze** — Gemini AI assesses each file with heuristic fallback
4. **Classify** — RAG scoring engine assigns threat levels
5. **Timeline** — Builds chronological event reconstruction

---

## Project Structure

```
├── app.py                  # Flask application (routes, DB, scan engine)
├── tools/
│   ├── scanner.py          # File system scanner
│   ├── hasher.py           # SHA-256 hash computation
│   ├── analyzer.py         # Gemini AI + heuristic analysis
│   ├── scorer.py           # RAG classification engine
│   ├── timeline.py         # Chronological event builder
│   ├── reporter.py         # Court-ready PDF generation
│   └── artifact_extractor.py  # Forensic artifact finder
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Layout with sidebar nav
│   ├── dashboard.html      # Case overview + stats
│   ├── new_case.html       # Case creation form
│   ├── case_detail.html    # Scan progress + evidence summary
│   ├── evidence.html       # Evidence gallery with filters
│   ├── timeline.html       # Forensic timeline view
│   └── report.html         # Report preview
├── static/
│   ├── css/style.css       # Dark forensic theme
│   └── js/app.js           # Scan progress + interactions
├── data/                   # SQLite DB + generated reports
├── requirements.txt
└── .env                    # API keys (not committed)
```

---

## Screenshots

### Dashboard
Dark forensic theme with case management and real-time stats.

### New Case
Officer-friendly form — case details, badge number, evidence source selection.

### Case Detail
5-step scan progress, RAG evidence summary, chain-of-custody log.

---

## Target Users

- Police officers and first responders
- Cyber crime unit investigators
- Non-technical law enforcement personnel
- Digital forensics trainees

---

## License

Built for Cyber Hackathon v4.0 & AMD Slingshot.

---

**Built with ❤️ for law enforcement.**
