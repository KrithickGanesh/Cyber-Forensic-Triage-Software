"""
Artifact Extractor — Extracts forensic artifacts from evidence.
Pulls browser history, recent files, USB history, and other forensic data.
"""

import os
import json
import sqlite3
from datetime import datetime


def extract_artifacts(scan_target):
    """
    Extract forensic artifacts from scan target.
    
    Args:
        scan_target: Path to evidence directory
    
    Returns:
        List of artifact dicts
    """
    artifacts = []
    
    # Try each extraction method
    artifacts.extend(find_browser_artifacts(scan_target))
    artifacts.extend(find_recent_documents(scan_target))
    artifacts.extend(find_registry_artifacts(scan_target))
    artifacts.extend(find_log_files(scan_target))
    
    return artifacts


def find_browser_artifacts(scan_target):
    """Find browser history, bookmarks, and cache files."""
    artifacts = []
    
    browser_paths = [
        # Chrome
        os.path.join('AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default'),
        # Firefox
        os.path.join('AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles'),
        # Edge
        os.path.join('AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default'),
    ]
    
    browser_files = ['History', 'Bookmarks', 'Login Data', 'Cookies', 'Web Data']
    
    for root, dirs, files in os.walk(scan_target):
        for filename in files:
            filepath = os.path.join(root, filename)
            
            # Check if this is a browser artifact
            is_browser = any(bp in filepath for bp in ['Chrome', 'Firefox', 'Edge', 'Opera', 'Brave'])
            if is_browser and filename in browser_files:
                artifacts.append({
                    'artifact_type': 'browser_data',
                    'file_path': filepath,
                    'file_name': filename,
                    'description': f"Browser artifact: {filename}",
                    'severity': 'AMBER',
                    'timestamp': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat() if os.path.exists(filepath) else None,
                })
    
    return artifacts


def find_recent_documents(scan_target):
    """Find recently accessed documents and shortcuts."""
    artifacts = []
    
    recent_extensions = {'.lnk', '.url', '.recent'}
    
    for root, dirs, files in os.walk(scan_target):
        # Look for Recent folder
        if 'Recent' in root or 'recent' in root:
            for filename in files:
                filepath = os.path.join(root, filename)
                _, ext = os.path.splitext(filename)
                
                if ext.lower() in recent_extensions:
                    artifacts.append({
                        'artifact_type': 'recent_document',
                        'file_path': filepath,
                        'file_name': filename,
                        'description': f"Recent file access: {filename}",
                        'severity': 'GREEN',
                        'timestamp': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat() if os.path.exists(filepath) else None,
                    })
    
    return artifacts


def find_registry_artifacts(scan_target):
    """Find Windows registry hive files."""
    artifacts = []
    
    registry_files = {
        'NTUSER.DAT': 'User registry hive — contains user preferences and activity',
        'SAM': 'Security Account Manager — contains user account data',
        'SYSTEM': 'System registry hive — contains system configuration',
        'SOFTWARE': 'Software registry hive — contains installed software',
        'SECURITY': 'Security registry hive — contains security policies',
        'UsrClass.dat': 'User class registry — contains shell data',
    }
    
    for root, dirs, files in os.walk(scan_target):
        for filename in files:
            if filename in registry_files:
                filepath = os.path.join(root, filename)
                artifacts.append({
                    'artifact_type': 'registry_hive',
                    'file_path': filepath,
                    'file_name': filename,
                    'description': registry_files[filename],
                    'severity': 'AMBER',
                    'timestamp': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat() if os.path.exists(filepath) else None,
                })
    
    return artifacts


def find_log_files(scan_target):
    """Find system and application log files."""
    artifacts = []
    
    log_extensions = {'.log', '.evtx', '.evt'}
    
    for root, dirs, files in os.walk(scan_target):
        for filename in files:
            _, ext = os.path.splitext(filename)
            
            if ext.lower() in log_extensions:
                filepath = os.path.join(root, filename)
                artifacts.append({
                    'artifact_type': 'log_file',
                    'file_path': filepath,
                    'file_name': filename,
                    'description': f"Log file: {filename}",
                    'severity': 'GREEN',
                    'timestamp': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat() if os.path.exists(filepath) else None,
                })
    
    return artifacts


def read_chrome_history(history_path):
    """
    Read Chrome browser history from SQLite database.
    Returns list of (url, title, visit_time) tuples.
    """
    entries = []
    try:
        conn = sqlite3.connect(history_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT url, title, last_visit_time 
            FROM urls 
            ORDER BY last_visit_time DESC 
            LIMIT 50
        """)
        for row in cursor.fetchall():
            entries.append({
                'url': row[0],
                'title': row[1],
                'visit_time': row[2],
            })
        conn.close()
    except Exception:
        pass
    
    return entries
