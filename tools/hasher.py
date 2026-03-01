"""
Hasher — SHA-256 hash computation for tamper-evident evidence integrity.
Computes hashes for every file processed. Integrity is non-negotiable.
"""

import hashlib
import os


def compute_sha256(filepath, chunk_size=8192):
    """
    Compute SHA-256 hash of a file.
    
    Args:
        filepath: Path to file to hash
        chunk_size: Read chunk size (8KB default for memory efficiency)
    
    Returns:
        SHA-256 hex digest string
    """
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, OSError):
        return None


def compute_md5(filepath, chunk_size=8192):
    """Compute MD5 hash (for VirusTotal lookups)."""
    md5 = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                md5.update(chunk)
        return md5.hexdigest()
    except (PermissionError, OSError):
        return None


def verify_integrity(filepath, expected_hash):
    """
    Verify file integrity by comparing SHA-256 hash.
    
    Returns:
        True if hash matches, False otherwise
    """
    actual_hash = compute_sha256(filepath)
    if actual_hash is None:
        return None
    return actual_hash == expected_hash


def hash_batch(file_list, progress_callback=None):
    """
    Hash a batch of files.
    
    Args:
        file_list: List of file paths
        progress_callback: Optional callback(current, total, filename)
    
    Returns:
        dict mapping filepath -> sha256 hash
    """
    results = {}
    total = len(file_list)
    
    for i, filepath in enumerate(file_list):
        sha256 = compute_sha256(filepath)
        if sha256:
            results[filepath] = sha256
        
        if progress_callback:
            progress_callback(i + 1, total, os.path.basename(filepath))
    
    return results
