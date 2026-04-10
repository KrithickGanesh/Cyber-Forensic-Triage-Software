# SOP: AI & Heuristic Analysis

## Objective
To provide an intelligent assessment of every file scanned, identifying potential threats or evidence.

## Procedure
1. **Gemini AI Analysis**:
    - Pass file metadata (name, type, size, path) to Google Gemini API.
    - Request a 2-3 sentence forensic assessment.
    - Focus on malicious associations, suspicious indicators, and recommended actions.
2. **Heuristic Fallback**:
    - If AI is unavailable, use rule-based analysis.
    - Check for executable extensions in non-standard locations.
    - Flag suspicious filenames (e.g., "passwords", "secret").
    - Identify hidden files and extension mismatches.
    - Detect large files and database files.

## Tools
- `tools/analyzer.py`
- Google Gemini API (`gemini-2.0-flash`)
- Python `mimetypes` and `stat`

## Data Output
- `ai_analysis` string for each evidence item.
- `flags` list for categorization.
