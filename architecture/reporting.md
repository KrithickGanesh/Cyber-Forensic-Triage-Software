# SOP: Court-Ready Reporting

## Objective
To generate a professional, tamper-evident PDF report that can be used as evidence in legal proceedings.

## Procedure
1. **Data Gathering**: Collect case details, executive summary (RAG counts), evidence list, timeline, and chain of custody.
2. **Integrity Check**: Ensure SHA-256 hashes are included for all evidence items.
3. **Structure**:
    - **Header**: Case ID, Officer, Date.
    - **Executive Summary**: Overall threat level and RAG distribution.
    - **Evidence Table**: Detailed list of flagged items with hashes.
    - **Timeline**: Chronological activity log.
    - **Chain of Custody**: Audit trail of who handled the evidence.
4. **Formatting**: Use a clean, professional layout with color-coded RAG indicators.

## Tools
- `tools/reporter.py`
- ReportLab (PDF generation engine)

## Data Output
- PDF file saved in `data/reports/`.
