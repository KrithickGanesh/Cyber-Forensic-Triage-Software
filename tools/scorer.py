"""
Scorer — RAG (Red-Amber-Green) evidence classifier.
Assigns threat levels with confidence scores based on multiple forensic signals.
"""

import os


# Extension risk categories
HIGH_RISK_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.scr', '.pif',
    '.com', '.msi', '.dll', '.sys', '.docm', '.xlsm', '.pptm',
    '.pgp', '.gpg', '.aes', '.enc', '.onion', '.torrent'
}

MEDIUM_RISK_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    '.iso', '.img', '.vhd', '.vmdk',
    '.db', '.sqlite', '.sqlite3', '.mdb', '.sql',
    '.wallet', '.dat', '.log', '.tmp', '.bak',
    '.reg', '.inf', '.lnk'
}

LOW_RISK_EXTENSIONS = {
    '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
    '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wav',
    '.html', '.htm', '.css', '.xml', '.json', '.csv',
    '.rtf', '.odt', '.ods'
}

# Suspicious path patterns
SUSPICIOUS_PATHS = [
    'temp', 'tmp', '$recycle', 'appdata', 'programdata',
    'startup', 'autorun', 'hidden', '.tor', 'darknet'
]

SUSPICIOUS_NAME_PATTERNS = [
    'password', 'credential', 'secret', 'keylog', 'bank',
    'account', 'login', 'dump', 'hack', 'crack', 'exploit',
    'ransom', 'decrypt', 'encrypt', 'backdoor', 'trojan',
    'malware', 'virus', 'worm', 'rootkit', 'phishing',
    'stolen', 'leaked', 'private', 'confidential'
]


def classify_file(file_info, virustotal_result=None):
    """
    Classify a file using the RAG system.
    
    Args:
        file_info: Dict with file metadata
        virustotal_result: Optional VirusTotal scan result
    
    Returns:
        tuple: (classification, confidence_score, flags)
        classification: 'RED' | 'AMBER' | 'GREEN'
        confidence_score: float 0.0 - 1.0
        flags: list of string reasons
    """
    score = 0  # Higher = more suspicious (0-100)
    flags = file_info.get('flags', [])
    
    ext = file_info.get('file_extension', '').lower()
    filename = file_info.get('file_name', '').lower()
    filepath = file_info.get('file_path', '').lower()
    file_size = file_info.get('file_size', 0)
    is_hidden = file_info.get('is_hidden', False)
    
    # 1. Extension-based scoring (0-30 points)
    if ext in HIGH_RISK_EXTENSIONS:
        score += 30
        if 'executable' not in flags:
            flags.append('high_risk_extension')
    elif ext in MEDIUM_RISK_EXTENSIONS:
        score += 15
        flags.append('medium_risk_extension')
    elif ext in LOW_RISK_EXTENSIONS:
        score += 0
    else:
        score += 5  # Unknown extensions get slight bump
        flags.append('unknown_extension')
    
    # 2. Filename pattern scoring (0-25 points)
    name_lower = os.path.splitext(filename)[0]
    for pattern in SUSPICIOUS_NAME_PATTERNS:
        if pattern in name_lower:
            score += 25
            if 'suspicious_name' not in flags:
                flags.append('suspicious_name')
            break
    
    # 3. Hidden file scoring (0-15 points)
    if is_hidden:
        score += 15
        if 'hidden' not in flags:
            flags.append('hidden')
    
    # 4. Path-based scoring (0-10 points)
    for pattern in SUSPICIOUS_PATHS:
        if pattern in filepath:
            score += 10
            flags.append('suspicious_path')
            break
    
    # 5. Size anomaly scoring (0-10 points)
    if file_size > 500 * 1024 * 1024:  # >500MB
        score += 10
        if 'large_file' not in flags:
            flags.append('large_file')
    elif file_size == 0:
        score += 5
        flags.append('empty_file')
    
    # 6. Extension mismatch (0-20 points)
    if 'extension_mismatch' in flags:
        score += 20
    
    # 7. VirusTotal results (0-40 points)
    if virustotal_result:
        if isinstance(virustotal_result, dict):
            positives = virustotal_result.get('positives', 0)
            if positives > 5:
                score += 40
                flags.append('virustotal_positive')
            elif positives > 0:
                score += 20
                flags.append('virustotal_suspect')
    
    # Normalize score to 0-100
    score = min(score, 100)
    
    # Convert to RAG classification
    if score >= 50:
        classification = 'RED'
        confidence = min(0.5 + (score - 50) / 100, 1.0)
    elif score >= 20:
        classification = 'AMBER'
        confidence = min(0.4 + (score - 20) / 75, 0.9)
    else:
        classification = 'GREEN'
        confidence = min(0.6 + (20 - score) / 50, 1.0)
    
    # Remove duplicate flags
    flags = list(dict.fromkeys(flags))
    
    return classification, round(confidence, 2), flags


def get_overall_threat_level(red_count, amber_count, green_count):
    """
    Determine overall case threat level from evidence counts.
    
    Returns: 'RED' | 'AMBER' | 'GREEN'
    """
    if red_count > 0:
        return 'RED'
    elif amber_count > 0:
        return 'AMBER'
    return 'GREEN'


def get_threat_summary(red_count, amber_count, green_count):
    """Generate a human-friendly threat summary."""
    total = red_count + amber_count + green_count
    if total == 0:
        return "No files scanned yet."
    
    parts = []
    if red_count > 0:
        parts.append(f"{red_count} high-priority item{'s' if red_count != 1 else ''} requiring immediate attention")
    if amber_count > 0:
        parts.append(f"{amber_count} item{'s' if amber_count != 1 else ''} flagged for review")
    if green_count > 0:
        parts.append(f"{green_count} item{'s' if green_count != 1 else ''} marked as clear")
    
    return '. '.join(parts) + '.'
