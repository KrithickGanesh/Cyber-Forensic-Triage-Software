# SOP: Evidence Classification (Scoring)

## Objective
To categorize evidence items into Red, Amber, or Green (RAG) threat levels based on forensic risk.

## Procedure
1. **Risk Scoring**:
    - **High Risk (+30)**: Executables, scripts, macro-enabled docs.
    - **Medium Risk (+15)**: Archives, disk images, database files.
    - **Suspicious Name (+25)**: Keywords like "password", "hack", "bank".
    - **Hidden Status (+15)**: Files with the hidden attribute.
    - **Suspicious Path (+10)**: Temp folders, AppData, Recycle Bin.
    - **Extension Mismatch (+20)**: File type does not match extension.
2. **Classification**:
    - **RED (Score >= 50)**: Immediate attention required.
    - **AMBER (Score 20-49)**: Flagged for manual review.
    - **GREEN (Score < 20)**: Likely safe/standard file.
3. **Confidence Scoring**: Assign a score (0.0 - 1.0) based on the strength of the signals.

## Tools
- `tools/scorer.py`

## Data Output
- `classification` (RED/AMBER/GREEN)
- `confidence_score`
- `flags`
