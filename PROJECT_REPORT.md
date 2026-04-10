# PROJECT REPORT: Cyber Forensic Triage Software
**An AI-Powered Portable Forensic Tool for Non-Technical Law Enforcement**

---

## 1. Executive Summary
The Cyber Forensic Triage Software is a modern, portable digital forensic tool designed for first responders and non-technical law enforcement officers. Traditional digital forensics faces significant backlogs due to the complexity and cost of existing tools. This project solves that problem by providing an autonomous, one-click triage system that uses **Google Gemini AI** and **VirusTotal** to identify critical evidence on-scene, reducing the need for immediate lab-based analysis.

---

## 2. Problem Statement
Digital forensic investigations are currently hampered by:
- **Long Backlogs:** Case processing takes months due to limited specialist availability.
- **Tool Complexity:** Existing software (EnCase, FTK) requires extensive training.
- **High Costs:** Licensing for professional forensic suites is prohibitively expensive ($3,000+).
- **Manual Triage:** Officers on-scene cannot quickly distinguish between a suspect's holiday photos and a hidden password database.

---

## 3. Proposed System
The proposed system is a web-based, portable application that can be run from a USB drive. It provides:
- **Automated Metadata Extraction:** Recursive scanning of target drives.
- **Cryptographic Integrity:** SHA-256 hashing for court-admissibility.
- **RAG Scoring Engine:** A Red-Amber-Green classification system for instant threat assessment.
- **Multimodal AI Analysis:** Using Gemini Vision to "read" images and identify sensitive content.
- **Global Threat Intelligence:** Integration with VirusTotal for malware hash lookups.

---

## 4. System Architecture (B.L.A.S.T. Protocol)
The system follows a 3-layer architecture:
1.  **Layer 1 (Architecture):** Standard Operating Procedures (SOPs) for data handling and integrity.
2.  **Layer 2 (Navigation):** A Flask-based decision engine that manages the scan pipeline.
3.  **Layer 3 (Tools):** Specialized Python scripts for scanning, hashing, scoring, and report generation.

---

## 5. Key Features & Implementation

### 5.1 AI-Powered Forensic Analysis (Gemini Vision)
The system utilizes the **Gemini-2.0-Flash** model. For images, the system performs multimodal analysis:
- **Visual OCR:** Extracts text from screenshots or documents.
- **Object Recognition:** Identifies evidentiary items like ID cards, weapons, or sensitive chat logs.
- **Contextual Summary:** Provides a 3-4 sentence forensic explanation of the image content.

### 5.2 RAG Threat Classification
Every file is passed through a scoring algorithm:
- **RED (Score > 50):** High-risk (Executables, encrypted archives, files with "password" in name).
- **AMBER (Score 20-49):** Suspicious (Hidden files, macro-enabled documents).
- **GREEN (Score < 20):** Standard (System files, common media).

### 5.3 Forensic Timeline & Artifacts
The system reconstructs a chronological sequence of events by extracting MAC (Modified, Accessed, Created) times, allowing investigators to visualize "bursts" of activity. It also identifies specialized forensic artifacts like browser history fragments and configuration backups.

---

## 6. Results & Discussion
During testing with the `sample_evidence` dataset, the system successfully:
1.  **Identified a Hidden Password List:** Flagged as RED due to filename and content analysis.
2.  **Detected a Malicious Executable:** Flagged as AMBER based on VirusTotal hash lookup.
3.  **Visualized a Chat Screenshot:** Using Gemini Vision, the system correctly identified a sensitive conversation regarding a "bank dump."
4.  **Generated a Court-Ready PDF:** Produced a professional report including SHA-256 hashes for all evidence.

---

## 7. Conclusion & Future Scope
The Cyber Forensic Triage Software successfully demonstrates how AI can democratize digital forensics. By automating the triage process, it empowers non-specialists to secure evidence quickly and accurately.

**Future Scope:**
- **Local LLM Integration:** Running Llama-3 locally for air-gapped forensic environments.
- **Live RAM Capture:** Adding memory forensics capabilities.
- **Blockchain Logs:** Using a private blockchain to log every user action for immutable chain-of-custody.

---
**Author:** Krithick Ganesh
**Academic Level:** 2nd Year Final Project
**Tools:** Python, Flask, SQLite, Google Gemini API, VirusTotal API, ReportLab
