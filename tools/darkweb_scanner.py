"""
Dark Web Indicator Scanner — Detects dark web artifacts and indicators.
Scans filenames, file contents (text-based), and browser artifacts for:
- .onion URLs (Tor hidden services)
- Cryptocurrency wallet addresses (BTC, ETH, XMR)
- Tor browser artifacts
- Known dark web marketplace references
- VPN/proxy configuration files
- Suspicious communication tools
"""

import os
import re
from datetime import datetime


# ─── Regex Patterns ───

ONION_URL_PATTERN = re.compile(
    r'[a-z2-7]{16,56}\.onion',
    re.IGNORECASE
)

# Bitcoin addresses (legacy P2PKH, P2SH, and Bech32)
BTC_ADDRESS_PATTERN = re.compile(
    r'\b(?:'
    r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'  # Legacy P2PKH / P2SH
    r'|bc1[a-zA-HJ-NP-Z0-9]{25,90}'      # Bech32
    r')\b'
)

# Ethereum addresses
ETH_ADDRESS_PATTERN = re.compile(
    r'\b0x[a-fA-F0-9]{40}\b'
)

# Monero addresses (95 chars starting with 4 or 8)
XMR_ADDRESS_PATTERN = re.compile(
    r'\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
)

# Tor-related filenames and paths
TOR_ARTIFACTS = {
    'tor.exe', 'tor-browser', 'torrc', 'tor-resolve',
    'torbrowser-install', 'tor browser', 'tor.lnk',
    'pluggable_transports', 'obfs4proxy.exe', 'snowflake-client.exe',
    'start-tor-browser', 'tor-gencert',
}

# VPN/Proxy indicators
VPN_PROXY_FILES = {
    'openvpn', '.ovpn', 'wireguard', '.wg', 'nordvpn',
    'protonvpn', 'mullvad', 'expressvpn', 'privoxy',
    'proxychains', 'shadowsocks', 'v2ray', 'trojan-go',
}

# Dark web marketplace and forum keywords
DARKWEB_KEYWORDS = [
    # Marketplaces
    'silk road', 'alphabay', 'dream market', 'wall street market',
    'hydra market', 'darkmarket', 'white house market', 'versus market',
    'bohemia market', 'incognito market', 'abacus market',
    # Forums
    'dread forum', 'darknet', 'dark web', 'deep web',
    'hidden wiki', 'torch search', 'ahmia',
    # Tools & services
    'pgp encrypt', 'tails os', 'whonix', 'i2p router',
    'bitcoin mixer', 'bitcoin tumbler', 'crypto tumbler',
    'monero wallet', 'electrum wallet',
    # Illegal activities
    'carding', 'fullz', 'cvv dump', 'credit card dump',
    'ransomware', 'exploit kit', 'zero day', 'botnet',
    'ddos service', 'stresser', 'booter',
    'phishing kit', 'stealer log', 'infostealer',
]

# Suspicious communication tools
SUSPICIOUS_COMM_TOOLS = {
    'signal', 'wickr', 'telegram', 'session',
    'briar', 'element', 'matrix', 'jabber',
    'pidgin', 'ricochet', 'cwtch',
}

# File extensions that could be dark web related
DARKWEB_EXTENSIONS = {
    '.onion', '.torrent', '.pgp', '.gpg', '.asc',
    '.wallet', '.keystore',
}

# Scannable text extensions
TEXT_EXTENSIONS = {
    '.txt', '.log', '.csv', '.json', '.xml', '.html', '.htm',
    '.md', '.cfg', '.conf', '.ini', '.yaml', '.yml',
    '.py', '.js', '.bat', '.cmd', '.ps1', '.sh',
    '.sql', '.url', '.lnk', '.rtf',
}


def scan_for_darkweb_indicators(scan_target):
    """
    Scan a directory for dark web indicators.
    
    Args:
        scan_target: Path to the evidence directory
    
    Returns:
        List of indicator dicts with type, value, file_path, severity, description
    """
    indicators = []
    
    for root, dirs, files in os.walk(scan_target):
        # Skip system directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in 
                   ['$Recycle.Bin', 'System Volume Information', 'Windows', '__pycache__']]
        
        for filename in files:
            filepath = os.path.join(root, filename)
            filename_lower = filename.lower()
            _, ext = os.path.splitext(filename)
            ext = ext.lower()
            
            # 1. Check filename for Tor artifacts
            for tor_name in TOR_ARTIFACTS:
                if tor_name in filename_lower:
                    indicators.append({
                        'indicator_type': 'tor_artifact',
                        'value': filename,
                        'file_path': filepath,
                        'severity': 'RED',
                        'confidence': 0.85,
                        'description': f'Tor browser artifact detected: {filename}',
                        'timestamp': _get_file_timestamp(filepath),
                    })
                    break
            
            # 2. Check for VPN/Proxy files
            for vpn_name in VPN_PROXY_FILES:
                if vpn_name in filename_lower:
                    indicators.append({
                        'indicator_type': 'vpn_proxy',
                        'value': filename,
                        'file_path': filepath,
                        'severity': 'AMBER',
                        'confidence': 0.65,
                        'description': f'VPN/Proxy configuration detected: {filename}',
                        'timestamp': _get_file_timestamp(filepath),
                    })
                    break
            
            # 3. Check for dark web related extensions
            if ext in DARKWEB_EXTENSIONS:
                indicators.append({
                    'indicator_type': 'darkweb_extension',
                    'value': f'{filename} ({ext})',
                    'file_path': filepath,
                    'severity': 'AMBER',
                    'confidence': 0.60,
                    'description': f'Dark web related file type: {ext}',
                    'timestamp': _get_file_timestamp(filepath),
                })
            
            # 4. Check filename for suspicious comm tools
            for tool in SUSPICIOUS_COMM_TOOLS:
                if tool in filename_lower:
                    indicators.append({
                        'indicator_type': 'encrypted_comms',
                        'value': filename,
                        'file_path': filepath,
                        'severity': 'AMBER',
                        'confidence': 0.55,
                        'description': f'Encrypted communication tool artifact: {filename}',
                        'timestamp': _get_file_timestamp(filepath),
                    })
                    break
            
            # 5. Scan text file contents for patterns
            if ext in TEXT_EXTENSIONS:
                try:
                    file_size = os.path.getsize(filepath)
                    if file_size > 50 * 1024 * 1024:  # Skip files > 50MB
                        continue
                    
                    content_indicators = _scan_file_content(filepath)
                    indicators.extend(content_indicators)
                    
                except (PermissionError, OSError):
                    pass
    
    # Remove duplicate indicators (same type + same file)
    seen = set()
    unique_indicators = []
    for ind in indicators:
        key = (ind['indicator_type'], ind['file_path'], ind.get('value', ''))
        if key not in seen:
            seen.add(key)
            unique_indicators.append(ind)
    
    return unique_indicators


def _scan_file_content(filepath):
    """Scan the content of a text file for dark web indicators."""
    indicators = []
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(1024 * 1024)  # Read max 1MB
    except Exception:
        return indicators
    
    content_lower = content.lower()
    
    # Check for .onion URLs
    onion_matches = ONION_URL_PATTERN.findall(content)
    if onion_matches:
        for match in onion_matches[:5]:  # Limit to 5 per file
            indicators.append({
                'indicator_type': 'onion_url',
                'value': match,
                'file_path': filepath,
                'severity': 'RED',
                'confidence': 0.95,
                'description': f'Tor hidden service URL found: {match[:20]}...onion',
                'timestamp': _get_file_timestamp(filepath),
            })
    
    # Check for Bitcoin addresses
    btc_matches = BTC_ADDRESS_PATTERN.findall(content)
    if btc_matches:
        for match in btc_matches[:3]:
            indicators.append({
                'indicator_type': 'crypto_wallet',
                'value': f'BTC: {match[:16]}...',
                'file_path': filepath,
                'severity': 'RED',
                'confidence': 0.80,
                'description': f'Bitcoin wallet address found: {match[:16]}...',
                'timestamp': _get_file_timestamp(filepath),
            })
    
    # Check for Ethereum addresses
    eth_matches = ETH_ADDRESS_PATTERN.findall(content)
    if eth_matches:
        for match in eth_matches[:3]:
            indicators.append({
                'indicator_type': 'crypto_wallet',
                'value': f'ETH: {match[:16]}...',
                'file_path': filepath,
                'severity': 'RED',
                'confidence': 0.80,
                'description': f'Ethereum wallet address found: {match[:16]}...',
                'timestamp': _get_file_timestamp(filepath),
            })
    
    # Check for Monero addresses
    xmr_matches = XMR_ADDRESS_PATTERN.findall(content)
    if xmr_matches:
        for match in xmr_matches[:3]:
            indicators.append({
                'indicator_type': 'crypto_wallet',
                'value': f'XMR: {match[:16]}...',
                'file_path': filepath,
                'severity': 'RED',
                'confidence': 0.85,
                'description': f'Monero wallet address found: {match[:16]}...',
                'timestamp': _get_file_timestamp(filepath),
            })
    
    # Check for dark web keywords
    found_keywords = []
    for keyword in DARKWEB_KEYWORDS:
        if keyword in content_lower:
            found_keywords.append(keyword)
    
    if found_keywords:
        keywords_str = ', '.join(found_keywords[:5])
        severity = 'RED' if len(found_keywords) >= 3 else 'AMBER'
        indicators.append({
            'indicator_type': 'darkweb_keyword',
            'value': keywords_str,
            'file_path': filepath,
            'severity': severity,
            'confidence': min(0.5 + len(found_keywords) * 0.1, 0.95),
            'description': f'Dark web keywords found ({len(found_keywords)}): {keywords_str}',
            'timestamp': _get_file_timestamp(filepath),
        })
    
    return indicators


def _get_file_timestamp(filepath):
    """Get file modification time as ISO string."""
    try:
        return datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
    except OSError:
        return datetime.now().isoformat()


def get_indicator_summary(indicators):
    """
    Generate a summary of dark web indicators found.
    
    Returns dict with counts by type and overall severity.
    """
    if not indicators:
        return {
            'total': 0,
            'severity': 'GREEN',
            'summary': 'No dark web indicators detected.',
            'by_type': {},
        }
    
    by_type = {}
    red_count = 0
    amber_count = 0
    
    for ind in indicators:
        itype = ind['indicator_type']
        by_type[itype] = by_type.get(itype, 0) + 1
        if ind['severity'] == 'RED':
            red_count += 1
        elif ind['severity'] == 'AMBER':
            amber_count += 1
    
    if red_count >= 3:
        severity = 'RED'
    elif red_count > 0 or amber_count >= 3:
        severity = 'AMBER'
    else:
        severity = 'GREEN'
    
    parts = []
    type_labels = {
        'onion_url': 'Tor hidden service URLs',
        'crypto_wallet': 'cryptocurrency wallet addresses',
        'tor_artifact': 'Tor browser artifacts',
        'vpn_proxy': 'VPN/proxy configurations',
        'darkweb_keyword': 'dark web keyword matches',
        'darkweb_extension': 'dark web file types',
        'encrypted_comms': 'encrypted communication tools',
    }
    
    for itype, count in by_type.items():
        label = type_labels.get(itype, itype)
        parts.append(f'{count} {label}')
    
    summary = f"Found {len(indicators)} dark web indicator(s): {'; '.join(parts)}."
    
    return {
        'total': len(indicators),
        'severity': severity,
        'summary': summary,
        'by_type': by_type,
        'red_count': red_count,
        'amber_count': amber_count,
    }
