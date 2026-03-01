"""
Timeline — Chronological event builder from file system timestamps.
Constructs a forensic timeline from file creation, modification, and access events.
"""

from datetime import datetime


def build_timeline(evidence_items):
    """
    Build a chronological timeline from evidence items.
    
    Args:
        evidence_items: List of file info dicts with timestamp fields
    
    Returns:
        List of timeline events sorted by timestamp
    """
    events = []
    
    for item in evidence_items:
        file_name = item.get('file_name', 'Unknown')
        file_path = item.get('relative_path', item.get('file_path', ''))
        classification = item.get('classification', 'GREEN')
        
        # File created event
        created = item.get('created_at')
        if created:
            events.append({
                'timestamp': created,
                'event_type': 'file_created',
                'description': f"File created: {file_name}",
                'source_file': file_path,
                'severity': classification,
                'file_name': file_name,
            })
        
        # File modified event
        modified = item.get('modified_at')
        if modified and modified != created:
            events.append({
                'timestamp': modified,
                'event_type': 'file_modified',
                'description': f"File modified: {file_name}",
                'source_file': file_path,
                'severity': classification,
                'file_name': file_name,
            })
        
        # File accessed event (only if different from created/modified)
        accessed = item.get('accessed_at')
        if accessed and accessed != created and accessed != modified:
            events.append({
                'timestamp': accessed,
                'event_type': 'file_accessed',
                'description': f"File accessed: {file_name}",
                'source_file': file_path,
                'severity': classification,
                'file_name': file_name,
            })
    
    # Sort by timestamp (newest first)
    events.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return events


def build_activity_clusters(timeline_events, window_minutes=30):
    """
    Group timeline events into activity clusters.
    
    Args:
        timeline_events: Sorted list of timeline events
        window_minutes: Time window for clustering (default 30 min)
    
    Returns:
        List of activity cluster dicts
    """
    if not timeline_events:
        return []
    
    clusters = []
    current_cluster = {
        'start_time': timeline_events[0]['timestamp'],
        'end_time': timeline_events[0]['timestamp'],
        'events': [timeline_events[0]],
        'max_severity': timeline_events[0]['severity'],
    }
    
    severity_rank = {'RED': 3, 'AMBER': 2, 'GREEN': 1}
    
    for event in timeline_events[1:]:
        try:
            current_end = datetime.fromisoformat(current_cluster['end_time'])
            event_time = datetime.fromisoformat(event['timestamp'])
            
            diff = abs((current_end - event_time).total_seconds() / 60)
            
            if diff <= window_minutes:
                current_cluster['events'].append(event)
                current_cluster['end_time'] = event['timestamp']
                
                if severity_rank.get(event['severity'], 0) > severity_rank.get(current_cluster['max_severity'], 0):
                    current_cluster['max_severity'] = event['severity']
            else:
                current_cluster['event_count'] = len(current_cluster['events'])
                clusters.append(current_cluster)
                current_cluster = {
                    'start_time': event['timestamp'],
                    'end_time': event['timestamp'],
                    'events': [event],
                    'max_severity': event['severity'],
                }
        except (ValueError, TypeError):
            continue
    
    # Don't forget the last cluster
    current_cluster['event_count'] = len(current_cluster['events'])
    clusters.append(current_cluster)
    
    return clusters


def format_timeline_for_display(events, limit=100):
    """Format timeline events for web display."""
    display_events = []
    
    for event in events[:limit]:
        try:
            ts = datetime.fromisoformat(event['timestamp'])
            formatted_time = ts.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            formatted_time = event.get('timestamp', 'Unknown')
        
        event_icons = {
            'file_created': '📄',
            'file_modified': '✏️',
            'file_accessed': '👁️',
            'artifact_found': '🔍',
        }
        
        display_events.append({
            'time': formatted_time,
            'icon': event_icons.get(event.get('event_type', ''), '📋'),
            'type': event.get('event_type', 'unknown').replace('_', ' ').title(),
            'description': event.get('description', ''),
            'source': event.get('source_file', ''),
            'severity': event.get('severity', 'GREEN'),
        })
    
    return display_events
