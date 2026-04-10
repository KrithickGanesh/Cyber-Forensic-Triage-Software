import os
import sqlite3
import json
from app import run_scan, init_db, DB_PATH

def test_forensic_scan():
    print("Initializing Database...")
    init_db()
    
    case_id = "test001"
    scan_target = os.path.abspath("sample_evidence")
    officer_name = "Test Officer"
    
    # Pre-populate case
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        INSERT OR REPLACE INTO cases (id, case_name, officer_name, scan_target, scan_type)
        VALUES (?, ?, ?, ?, ?)
    ''', (case_id, "Test Sample Case", officer_name, scan_target, "uploaded_folder"))
    conn.commit()
    conn.close()
    
    print(f"Starting scan on {scan_target}...")
    run_scan(case_id, scan_target, officer_name)
    
    print("\nScan Complete! Results:")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    case = conn.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone()
    print(f"Overall Threat Level: {case['threat_level']}")
    print(f"Total Files: {case['total_files']}")
    print(f"RED: {case['red_count']}, AMBER: {case['amber_count']}, GREEN: {case['green_count']}")
    
    print("\nFlagged Evidence:")
    evidence = conn.execute('SELECT * FROM evidence WHERE case_id = ? AND classification IN ("RED", "AMBER") ORDER BY classification DESC', (case_id,)).fetchall()
    for item in evidence:
        print(f"[{item['classification']}] {item['file_name']} - Flags: {item['flags']}")
    
    print("\nTimeline Events (Top 10):")
    timeline = conn.execute('SELECT * FROM timeline WHERE case_id = ? ORDER BY timestamp DESC LIMIT 10', (case_id,)).fetchall()
    for event in timeline:
        print(f"[{event['severity']}] {event['timestamp']} - {event['event_type']}: {event['description']}")
    
    conn.close()

if __name__ == "__main__":
    test_forensic_scan()
