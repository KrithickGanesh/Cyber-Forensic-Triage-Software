"""
Analyzer — AI-powered file analysis using Google Gemini API.
Provides intelligent file assessment and suspicious activity detection.
Falls back to heuristic analysis if API is unavailable.
"""

import os
import json
from dotenv import load_dotenv

load_dotenv()


def get_gemini_client():
    """Initialize Gemini AI client."""
    try:
        import google.generativeai as genai
        api_key = os.getenv('GEMINI_API_KEY')
        if not api_key:
            return None
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.0-flash-lite')
        return model
    except Exception:
        return None


import requests

def get_vt_result(file_hash):
    """
    Look up a file hash on VirusTotal.
    
    Args:
        file_hash: SHA-256 or MD5 hash
    
    Returns:
        Dict with VT results or None
    """
    vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not vt_api_key:
        return None
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": vt_api_key
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {
                'positives': stats.get('malicious', 0),
                'total': sum(stats.values()),
                'details': data
            }
        return None
    except Exception:
        return None


import PIL.Image

def analyze_with_ai(file_info, model=None):
    """
    Analyze file using Gemini AI for forensic assessment.
    Supports Gemini Vision for image files.
    """
    if model is None:
        model = get_gemini_client()
    
    if model is None:
        return heuristic_analysis(file_info)

    file_path = file_info.get('file_path')
    ext = file_info.get('file_extension', '').lower()
    is_image = ext in {'.jpg', '.jpeg', '.png', '.webp'}
    
    # Base prompt for metadata analysis
    prompt = f"""You are a digital forensics expert. Analyze this file and provide a forensic assessment.
File: {file_info.get('file_name', 'unknown')}
Type: {file_info.get('file_type', 'unknown')}
Size: {file_info.get('file_size', 0)} bytes
Path: {file_info.get('relative_path', 'unknown')}
"""

    # If it's an image and small enough, use Gemini Vision
    if is_image and file_path and os.path.exists(file_path) and file_info.get('file_size', 0) < 10 * 1024 * 1024:
        vision_prompt = prompt + """
[CRITICAL FORENSIC IMAGE ANALYSIS]
This is an image file found on a suspect's device. You MUST analyze the VISUAL content:
1. What exactly is depicted in this image?
2. Are there any IDs, passwords, bank details, or sensitive text?
3. Is this a screenshot of a chat, a system setting, or a web page?
4. Flag any suspicious, criminal, or evidentiary items.

Provide a 3-4 sentence forensic summary. Do NOT just analyze the filename; analyze the VISUAL pixels."""
        
        try:
            print(f"[AI] Attempting Vision Analysis for: {file_info.get('file_name')}")
            img = PIL.Image.open(file_path)
            # Use a list to pass prompt and image
            response = model.generate_content([vision_prompt, img])
            if response and response.text:
                return response.text.strip()
        except Exception as e:
            # Log the error to your terminal so you can see it!
            print(f"[ERROR] Gemini Vision failed for {file_info.get('file_name')}: {str(e)}")
            # If it's a "Model not found" or similar, maybe the API version is different
            pass

    # Standard metadata prompt (Fallback or for non-images)
    metadata_prompt = prompt + """
Provide a 2-3 sentence forensic assessment based on this metadata. 
1. Malicious associations for this file type/location.
2. Suspicious indicators (hidden, timestamp anomalies).
3. Recommended action (flag for review / mark as safe)."""

    try:
        response = model.generate_content(metadata_prompt)
        return response.text.strip()
    except Exception as e:
        print(f"[ERROR] Gemini Metadata Analysis failed: {str(e)}")
        return heuristic_analysis(file_info)


def heuristic_analysis(file_info):
    """
    Fallback heuristic analysis when AI is unavailable.
    Uses rule-based assessment.
    """
    findings = []
    flags = []
    
    filename = file_info.get('file_name', '').lower()
    ext = file_info.get('file_extension', '').lower()
    file_size = file_info.get('file_size', 0)
    is_hidden = file_info.get('is_hidden', False)
    file_type = file_info.get('file_type', '')
    
    # Check for executable files
    executable_exts = {'.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.scr', '.pif', '.com', '.msi', '.dll'}
    if ext in executable_exts:
        findings.append(f"Executable file detected ({ext}). Executables can contain malware and should be reviewed.")
        flags.append('executable')
    
    # Check for encrypted/archive files
    archive_exts = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.enc', '.pgp', '.gpg'}
    if ext in archive_exts:
        findings.append(f"Archive/encrypted file detected ({ext}). Could be used for data exfiltration or hiding content.")
        flags.append('archive_encrypted')
    
    # Check for documents with macros
    macro_exts = {'.docm', '.xlsm', '.pptm'}
    if ext in macro_exts:
        findings.append(f"Macro-enabled document detected ({ext}). Macros can execute malicious code.")
        flags.append('macro_document')
    
    # Check for hidden files
    if is_hidden:
        findings.append("Hidden file detected. Hidden files may be used to conceal evidence or malware.")
        flags.append('hidden')
    
    # Check for suspicious filenames
    suspicious_names = {'passwords', 'credentials', 'secret', 'keylog', 'bank', 'accounts', 'logins', 'dump', 'hack', 'crack', 'exploit'}
    name_without_ext = os.path.splitext(filename)[0]
    if any(word in name_without_ext for word in suspicious_names):
        findings.append(f"Suspicious filename detected: '{filename}'. Requires immediate review.")
        flags.append('suspicious_name')
    
    # Check for large files
    if file_size > 100 * 1024 * 1024:  # 100MB
        findings.append(f"Large file ({file_size / (1024*1024):.1f} MB). Large files may indicate data dumps or disk images.")
        flags.append('large_file')
    
    # Check for database files
    db_exts = {'.db', '.sqlite', '.sqlite3', '.mdb', '.accdb', '.sql'}
    if ext in db_exts:
        findings.append(f"Database file detected ({ext}). May contain structured sensitive data.")
        flags.append('database')
    
    # Check for image/video (potential CSAM or evidence)
    media_exts = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.mp4', '.avi', '.mkv', '.mov', '.wmv'}
    if ext in media_exts:
        findings.append(f"Media file detected ({ext}). May contain photographic or video evidence.")
        flags.append('media')
    
    # Extension mismatch check
    if file_type and ext:
        type_ext_map = {
            'application/pdf': '.pdf',
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'text/plain': '.txt',
        }
        expected_ext = type_ext_map.get(file_type)
        if expected_ext and ext != expected_ext and ext not in ('.jpeg',):
            findings.append(f"Extension mismatch: file type is {file_type} but extension is {ext}. File may be disguised.")
            flags.append('extension_mismatch')
    
    if not findings:
        findings.append(f"Standard file ({ext or 'unknown type'}). No immediate forensic concerns detected.")
    
    analysis = ' '.join(findings)
    file_info['flags'] = flags
    
    return analysis


def analyze_batch(file_list, use_ai=True, progress_callback=None):
    """
    Analyze a batch of files.
    
    Args:
        file_list: List of file info dicts
        use_ai: Whether to use Gemini AI (True) or heuristic only (False)
        progress_callback: Optional callback(current, total, filename)
    
    Returns:
        List of file info dicts with 'ai_analysis' field added
    """
    model = get_gemini_client() if use_ai else None
    total = len(file_list)
    
    for i, file_info in enumerate(file_list):
        if model and use_ai:
            file_info['ai_analysis'] = analyze_with_ai(file_info, model)
        else:
            file_info['ai_analysis'] = heuristic_analysis(file_info)
        
        if progress_callback:
            progress_callback(i + 1, total, file_info.get('file_name', 'unknown'))
    
    return file_list
