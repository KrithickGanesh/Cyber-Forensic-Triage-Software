# Cyber Forensic Triage Software — Project Constitution
> `gemini.md` is *law*. This file defines data schemas, behavioral rules, and architectural invariants.

---

## Project Identity
- **Name:** Cyber Forensic Triage Software
- **Purpose:** AI-powered portable forensic triage tool for non-technical law enforcement
- **Target Users:** Police officers, first responders (zero training required)
- **Platform:** Web-based UI (Flask backend), designed for USB portability
- **Hackathon:** Cyber Hackathon v4.0 + AMD Slingshot

---

## Data Schemas

### Input Schema (Evidence Ingestion)
```json
{
  "case": {
    "case_id": "string (auto-generated UUID)",
    "case_name": "string",
    "officer_name": "string",
    "badge_number": "string",
    "department": "string",
    "created_at": "ISO 8601 timestamp",
    "scan_target": "string (directory/drive path)",
    "scan_type": "usb_drive | disk_image | uploaded_folder"
  }
}
```

### Output Schema (Triage Report)
```json
{
  "report": {
    "case_id": "string",
    "scan_summary": {
      "total_files_scanned": "integer",
      "total_size_bytes": "integer",
      "scan_duration_seconds": "float",
      "threat_level": "RED | AMBER | GREEN",
      "red_count": "integer",
      "amber_count": "integer",
      "green_count": "integer"
    },
    "evidence_items": [
      {
        "id": "integer (auto)",
        "file_path": "string",
        "file_name": "string",
        "file_type": "string",
        "file_size": "integer",
        "sha256_hash": "string",
        "classification": "RED | AMBER | GREEN",
        "confidence_score": "float (0.0 - 1.0)",
        "flags": ["string"],
        "metadata": {},
        "timestamp": "ISO 8601",
        "ai_analysis": "string (Gemini AI summary)",
        "virustotal_result": "string | null"
      }
    ],
    "timeline": [
      {
        "timestamp": "ISO 8601",
        "event_type": "file_created | file_modified | file_accessed | artifact_found",
        "description": "string",
        "source_file": "string",
        "severity": "RED | AMBER | GREEN"
      }
    ],
    "chain_of_custody": [
      {
        "timestamp": "ISO 8601",
        "action": "string",
        "performed_by": "string",
        "details": "string"
      }
    ],
    "generated_at": "ISO 8601"
  }
}
```

### Database Schema (SQLite)
```sql
-- Cases table
CREATE TABLE cases (
    id TEXT PRIMARY KEY,
    case_name TEXT NOT NULL,
    officer_name TEXT NOT NULL,
    badge_number TEXT,
    department TEXT,
    scan_target TEXT NOT NULL,
    scan_type TEXT DEFAULT 'uploaded_folder',
    status TEXT DEFAULT 'pending',
    threat_level TEXT DEFAULT 'GREEN',
    total_files INTEGER DEFAULT 0,
    red_count INTEGER DEFAULT 0,
    amber_count INTEGER DEFAULT 0,
    green_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

-- Evidence items table
CREATE TABLE evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_type TEXT,
    file_size INTEGER,
    sha256_hash TEXT,
    classification TEXT DEFAULT 'GREEN',
    confidence_score REAL DEFAULT 0.0,
    flags TEXT,
    metadata TEXT,
    ai_analysis TEXT,
    virustotal_result TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

-- Timeline events table
CREATE TABLE timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TIMESTAMP,
    event_type TEXT,
    description TEXT,
    source_file TEXT,
    severity TEXT DEFAULT 'GREEN',
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

-- Chain of custody table
CREATE TABLE chain_of_custody (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,
    performed_by TEXT,
    details TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

-- Audit log table
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,
    details TEXT,
    case_id TEXT
);
```

---

## Behavioral Rules

### DO
- Always compute SHA-256 hashes for every file processed
- Always maintain chain-of-custody logs
- Always use RAG (Red-Amber-Green) classification
- Always generate court-admissible reports
- Keep UI simple enough for non-technical users
- Log all actions for audit trail
- Use minimal system impact during scans
- Support Windows XP+ compatibility

### DO NOT
- Never modify original evidence files
- Never delete or overwrite scan results
- Never skip hashing (integrity is non-negotiable)
- Never use jargon in the UI — plain language only
- Never auto-delete temporary files without logging

---

## Integrations
- **VirusTotal API:** Malware hash lookup (API key required in `.env`)
- **Google Gemini AI:** Intelligent file analysis and summarization (API key required in `.env`)
- **Threat Intelligence:** YARA rules, known-bad hash databases

---

## Architectural Invariants

### Tech Stack
- **Backend:** Python + Flask
- **Database:** SQLite (portable, no server needed)
- **Frontend:** HTML + Vanilla CSS + JavaScript
- **Reporting:** ReportLab (PDF generation)
- **Hashing:** hashlib (SHA-256)
- **File Analysis:** os, stat, python-magic, exifread
- **AI:** Google Gemini API
- **Threat Intel:** VirusTotal API, YARA rules
- **Version Control:** Git + GitHub

### File Structure (A.N.T. Architecture)
```
├── gemini.md              # Project Constitution (this file)
├── task_plan.md           # Phase tracker
├── findings.md            # Research log
├── progress.md            # Work log
├── .env                   # API keys
├── architecture/          # Layer 1: SOPs
│   ├── scanning.md
│   ├── analysis.md
│   ├── timeline.md
│   ├── reporting.md
│   └── scoring.md
├── tools/                 # Layer 3: Python engines
│   ├── scanner.py
│   ├── hasher.py
│   ├── analyzer.py
│   ├── timeline.py
│   ├── scorer.py
│   ├── reporter.py
│   └── artifact_extractor.py
├── app.py                 # Layer 2: Navigation (Flask)
├── templates/             # Jinja2 HTML templates
├── static/                # CSS, JS, images
│   ├── css/
│   ├── js/
│   └── img/
├── data/                  # SQLite DB + case data
├── .tmp/                  # Temporary workbench
└── requirements.txt
```

---

## Maintenance Log
- **2026-03-01:** Project initialized. B.L.A.S.T. Protocol 0 complete.
- **2026-03-01:** Discovery answers received. Data schemas finalized. GitHub repo created.
