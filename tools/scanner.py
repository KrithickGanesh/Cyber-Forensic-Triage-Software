"""
Scanner — Recursive file system scanning engine.
Scans directories, USB drives, and mounted images with minimal system impact.
Collects file metadata: size, timestamps, type, permissions.
"""

import os
import stat
import time
import mimetypes
from datetime import datetime


def scan_directory(target_path, progress_callback=None):
    """
    Recursively scan a directory and collect file metadata.
    
    Args:
        target_path: Path to the directory/drive to scan
        progress_callback: Optional callback(current, total, filename) for progress updates
    
    Returns:
        list of dicts with file metadata
    """
    results = []
    errors = []
    total_size = 0
    start_time = time.time()

    # First pass: count total files for progress tracking
    total_files = 0
    for root, dirs, files in os.walk(target_path):
        # Skip system/hidden directories to minimize impact
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in 
                   ['$Recycle.Bin', 'System Volume Information', 'Windows', 'ProgramData']]
        total_files += len(files)

    # Second pass: collect metadata
    scanned = 0
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in 
                   ['$Recycle.Bin', 'System Volume Information', 'Windows', 'ProgramData']]
        
        for filename in files:
            filepath = os.path.join(root, filename)
            scanned += 1

            try:
                file_stat = os.stat(filepath)
                file_size = file_stat.st_size
                total_size += file_size

                # Get MIME type
                mime_type, _ = mimetypes.guess_type(filepath)
                if mime_type is None:
                    mime_type = 'application/octet-stream'

                # Get file extension
                _, ext = os.path.splitext(filename)
                ext = ext.lower()

                # Collect timestamps
                created_time = datetime.fromtimestamp(file_stat.st_ctime).isoformat()
                modified_time = datetime.fromtimestamp(file_stat.st_mtime).isoformat()
                accessed_time = datetime.fromtimestamp(file_stat.st_atime).isoformat()

                # Check permissions
                is_hidden = filename.startswith('.') or bool(file_stat.st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN) if hasattr(file_stat, 'st_file_attributes') else filename.startswith('.')
                is_readonly = not os.access(filepath, os.W_OK)

                file_info = {
                    'file_path': filepath,
                    'file_name': filename,
                    'file_type': mime_type,
                    'file_extension': ext,
                    'file_size': file_size,
                    'created_at': created_time,
                    'modified_at': modified_time,
                    'accessed_at': accessed_time,
                    'is_hidden': is_hidden,
                    'is_readonly': is_readonly,
                    'relative_path': os.path.relpath(filepath, target_path),
                }

                results.append(file_info)

                if progress_callback:
                    progress_callback(scanned, total_files, filename)

            except PermissionError:
                errors.append({'file': filepath, 'error': 'Permission denied'})
            except OSError as e:
                errors.append({'file': filepath, 'error': str(e)})

    scan_duration = time.time() - start_time

    return {
        'files': results,
        'errors': errors,
        'total_files': len(results),
        'total_size': total_size,
        'scan_duration': round(scan_duration, 2),
        'target_path': target_path,
        'scanned_at': datetime.now().isoformat()
    }


# Suspicious file extensions for forensic analysis
SUSPICIOUS_EXTENSIONS = {
    # Executables & Scripts
    '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.scr', '.pif',
    '.com', '.msi', '.dll', '.sys',
    # Archives (potential data exfiltration)
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    # Documents with macros
    '.docm', '.xlsm', '.pptm',
    # Encrypted/password files
    '.pgp', '.gpg', '.aes', '.enc',
    # Disk images
    '.iso', '.img', '.vhd', '.vmdk',
    # Database files
    '.db', '.sqlite', '.mdb',
    # Cryptocurrency
    '.wallet', '.dat',
    # Tor/Dark web related
    '.onion',
}

SUSPICIOUS_FILENAMES = {
    'passwords.txt', 'credentials.txt', 'secret.txt', 'keylog.txt',
    'bank.txt', 'accounts.txt', 'logins.txt', 'dump.sql',
    'tor.exe', 'vpn.exe', 'proxy.exe',
}


def get_suspicious_extensions():
    """Return set of suspicious file extensions."""
    return SUSPICIOUS_EXTENSIONS


def get_suspicious_filenames():
    """Return set of suspicious filenames."""
    return SUSPICIOUS_FILENAMES
