# CYBER FORENSIC TRIAGE SOFTWARE: AN AI-POWERED PORTABLE FORENSIC TOOL FOR NON-TECHNICAL LAW ENFORCEMENT

**A PROJECT REPORT**

*Submitted by*
**KRITHICK GANESH (Reg No: Your_Reg_No)**

*In partial fulfilment for the award of the degree of*
**BACHELOR OF TECHNOLOGY**
in
**INFORMATION TECHNOLOGY**

**EASWARI ENGINEERING COLLEGE, RAMAPURAM**
(Autonomous Institution)
*affiliated to*
**ANNA UNIVERSITY : CHENNAI 600025**
**APRIL 2026**

---

## BONAFIDE CERTIFICATE
Certified that this project report titled **“CYBER FORENSIC TRIAGE SOFTWARE: AN AI-POWERED PORTABLE FORENSIC TOOL FOR NON-TECHNICAL LAW ENFORCEMENT”** is the Bonafide work of **“KRITHICK GANESH (Reg No: Your_Reg_No)”** who carried out the project work under my supervision.

**SIGNATURE**
**HEAD OF THE DEPARTMENT**
Professor
Information Technology
Easwari Engineering College
Ramapuram, Chennai - 600089

---

## ABSTRACT
The digital forensics industry currently faces a critical crisis characterized by massive case backlogs and a shortage of specialized investigators. Traditional forensic tools, while powerful, are expensive and require extensive training, making them inaccessible to first responders. This project, **Cyber Forensic Triage Software**, addresses these challenges by providing an autonomous, portable triage tool designed for non-technical law enforcement personnel.

The system leverages a modern technology stack including **Python (Flask)**, **SQLite**, and integrates state-of-the-art Multimodal AI via the **Google Gemini API** and threat intelligence via the **VirusTotal API**. The core innovation lies in its ability to "read" visual evidence through Gemini Vision, allowing the tool to automatically identify sensitive documents, chat logs, and illicit content in images without human intervention. By implementing a Red-Amber-Green (RAG) scoring engine and ensuring cryptographic integrity through SHA-256 hashing, the software provides on-scene investigators with a court-ready triage report in minutes rather than months.

---

## TABLE OF CONTENTS
1.  **INTRODUCTION**
    1.1 Overview
    1.2 Objective
    1.3 Project Definition
    1.4 Project Motivation
2.  **RELATED WORK**
3.  **SYSTEM ANALYSIS**
    3.1 Problem Analysis
    3.2 Proposed Solution
    3.3 System Requirements Specification
4.  **SYSTEM DESIGN**
    4.1 System Architecture (3-Layer Build)
    4.2 Database Design
    4.3 Data Flow
5.  **SYSTEM IMPLEMENTATION**
    5.1 AI & Multimodal Integration
    5.2 Threat Intelligence Integration
6.  **SYSTEM TESTING**
7.  **OUTPUT AND EXPLANATION**
8.  **RESULT AND DISCUSSION**
9.  **CONCLUSION AND FUTURE WORK**
10. **REFERENCES**

---

## CHAPTER 1: INTRODUCTION

### 1.1 OVERVIEW
Cyber Forensic Triage Software is an innovative solution designed to bridge the gap between crime scene evidence collection and lab-based forensic analysis. In the current landscape, digital evidence is often left un-triaged for months, leading to missed leads. This tool enables any officer to plug in a drive and receive an instant intelligence summary.

### 1.2 OBJECTIVE
The primary objective is to automate the identification of evidentiary artifacts. Key goals include:
- Implementing high-speed recursive scanning.
- Ensuring 100% data integrity using SHA-256 hashes.
- Utilizing Multimodal AI to analyze images and documents.
- Generating professional, court-admissible PDF reports.

### 1.3 PROJECT DEFINITION
The tool is defined as a portable web application that performs automated forensic triage. It categorizes files based on risk and provides a chronological timeline of user activity.

---

## CHAPTER 3: SYSTEM ANALYSIS

### 3.1 PROBLEM ANALYSIS
- **Backlogs:** 9-12 month average wait time for digital forensic labs.
- **Complexity:** Current tools like EnCase require 40+ hours of training.
- **Manual Labor:** Investigators must manually view thousands of images to find one piece of evidence.

### 3.2 PROPOSED SOLUTION
The proposed system automates the "first look." By using AI Vision, the software can scan 1,000 images and flag the 5 that contain bank details or chat logs, saving hours of manual review.

### 3.3 SYSTEM REQUIREMENTS
- **Software:** Python 3.9+, Flask, ReportLab, Google Generative AI SDK.
- **Hardware:** Minimal requirements; optimized for USB portability.

---

## CHAPTER 4: SYSTEM DESIGN

### 4.1 SYSTEM ARCHITECTURE (A.N.T. ARCHITECTURE)
The project follows a unique 3-layer architectural pattern:
1.  **Layer 1 (Architecture - SOPs):** Defines the legal and forensic standards for data handling.
2.  **Layer 2 (Navigation - Flask):** The core decision engine managing the scan pipeline.
3.  **Layer 3 (Tools - Python Engines):** Specialized modules for hashing (`hasher.py`), scanning (`scanner.py`), and AI analysis (`analyzer.py`).

### 4.2 DATABASE DESIGN
The system utilizes a portable **SQLite** database with five primary tables: `cases`, `evidence`, `timeline`, `chain_of_custody`, and `audit_log`. This ensures that every action is logged and every piece of evidence is indexed with its cryptographic hash.

---

## CHAPTER 5: SYSTEM IMPLEMENTATION

### 5.1 MULTIMODAL AI (GEMINI VISION)
A standout feature of the implementation is the use of **Gemini-2.0-Flash**. Unlike traditional tools that only check filenames, this system opens image files and uses AI to "see" the pixels. It identifies:
- **OCR:** Text within screenshots.
- **Context:** Identification of ID cards, weapons, or financial documents.

### 5.2 VIRUSTOTAL INTEGRATION
To detect malware, the system computes the SHA-256 hash of every executable and queries the VirusTotal API. This allows the software to flag known trojans or ransomware without needing a local antivirus database.

---

## CHAPTER 9: CONCLUSION AND FUTURE WORK

### 9.1 CONCLUSION
The Cyber Forensic Triage Software successfully demonstrates that AI can significantly reduce the technical barrier to digital forensics. By automating complex tasks like image analysis and malware detection, the tool empowers first responders to secure digital evidence efficiently and accurately.

### 9.2 FUTURE WORK
- **Offline Mode:** Integration of local LLMs (like Llama-3) for use in secure, air-gapped environments.
- **Blockchain Logs:** Utilizing a private blockchain ledger for immutable chain-of-custody documentation.
- **Mobile App:** Developing a companion app for rapid on-scene documentation and photo evidence.

---

## CHAPTER 10: REFERENCES
1. NIST Special Publication 800-86: Guide to Integrating Forensic Techniques into Incident Response.
2. Google Gemini API Documentation: Multimodal prompt engineering for forensic tasks.
3. VirusTotal API v3 Documentation: Automated hash lookup for malware detection.
