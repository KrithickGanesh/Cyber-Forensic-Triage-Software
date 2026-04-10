# SOP: Device Scanning

## Objective
To recursively scan a target device or directory for all files while maintaining system integrity and minimizing forensic footprint.

## Procedure
1. **Target Identification**: Identify the drive letter or directory path of the evidence.
2. **Exclusion List**: Ensure system directories (e.g., `C:\Windows`, `$Recycle.Bin`) are skipped to reduce noise and speed up the scan.
3. **Metadata Collection**: For each file found, collect:
    - Full file path
    - File name and extension
    - File size (bytes)
    - Timestamps (Creation, Modification, Access)
    - MIME type
    - File attributes (Hidden, Read-only)
4. **Progress Tracking**: Provide real-time updates on the number of files scanned.

## Tools
- `tools/scanner.py`
- `os.walk` for recursion
- `os.stat` for metadata

## Data Output
- A list of file metadata dictionaries.
