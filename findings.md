# Findings — Research & Discoveries

## GitHub Research (2026-03-01)

### Reference Repos Found
1. **kavya-7777/CyberTriageTool** ⭐ Most relevant
   - Flask backend + Python forensic modules
   - Modules: analysis, hashing, scoring, timeline, YARA, IOC detection, reporting
   - Tech: Flask, SQLite, ReportLab, Tailwind CSS
   - Structure: `modules/`, `templates/`, `static/`, `scripts/`, `data/`
   
2. **scolemanjr/cyber-triage-tool**
   - Basic digital forensics tool for DFIR workflows
   
3. **JJBHBJBH/CYB-TRI**
   - Forensic triage with automated analysis & reporting

### Key Technical Patterns Observed
- Flask is the dominant backend for forensic web tools
- SQLite for local case storage (portable)
- SHA-256 for tamper-evident hashing
- ReportLab for PDF court-ready reports
- Modular architecture (separate files for scanning, hashing, analysis, scoring, timeline)
- YARA rules for malware/pattern detection
- IOC (Indicators of Compromise) matching

### Competitive Analysis (From PDF)
| Feature | Cyber Triage | Autopsy | EnCase | **Our Solution** |
|---------|-------------|---------|--------|-----------------|
| Cost | $2,500+ | Free/Limited | $3,500+ | **Affordable** |
| Training Required | Extensive | Moderate | Extensive | **Zero** |
| AI Powered | Limited | No | No | **Yes** |
| On-Scene Use | Limited | No | No | **Yes (USB)** |
| Processing Speed | Hours | Days | Hours | **<30 min** |

## Constraints Identified
- Must work on Windows XP+ (broad compatibility)
- USB-portable design (self-contained)
- Non-technical users (police officers) — UI must be dead simple
- Court-ready output (legal formatting requirements)
- RAG (Red-Amber-Green) classification system for evidence priority
- 24-hour hackathon scope — need working prototype + demo interface
