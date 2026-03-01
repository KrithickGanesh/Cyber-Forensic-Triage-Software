"""
Cyber Forensic Triage Software — Main Application
Layer 2: Navigation (Flask)

AI-powered portable forensic triage tool for non-technical law enforcement.
"""

import os
import uuid
import json
import sqlite3
import threading
import time
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, send_file, session
)
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import tools
from tools.scanner import scan_directory
from tools.hasher import compute_sha256
from tools.analyzer import analyze_with_ai, heuristic_analysis, get_gemini_client
from tools.scorer import classify_file, get_overall_threat_level, get_threat_summary
from tools.timeline import build_timeline, format_timeline_for_display
from tools.reporter import generate_report
from tools.artifact_extractor import extract_artifacts

# ─── Flask App Configuration ───
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'forensic-triage-default-key')
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB upload limit

# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'forensic.db')
REPORTS_DIR = os.path.join(os.path.dirname(__file__), 'data', 'reports')
EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), 'evidence')
TMP_DIR = os.path.join(os.path.dirname(__file__), '.tmp')

# Ensure directories exist
for d in [os.path.dirname(DB_PATH), REPORTS_DIR, EVIDENCE_DIR, TMP_DIR]:
    os.makedirs(d, exist_ok=True)

# Active scans tracking
active_scans = {}


# ─── Database ───
def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Initialize database tables."""
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            case_name TEXT NOT NULL,
            officer_name TEXT NOT NULL,
            badge_number TEXT,
            department TEXT,
            scan_target TEXT NOT NULL,
            scan_type TEXT DEFAULT 'uploaded_folder',
            status TEXT DEFAULT 'pending',
            threat_level TEXT DEFAULT 'GREEN',
            total_files INTEGER DEFAULT 0,
            red_count INTEGER DEFAULT 0,
            amber_count INTEGER DEFAULT 0,
            green_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_type TEXT,
            file_extension TEXT,
            file_size INTEGER,
            sha256_hash TEXT,
            classification TEXT DEFAULT 'GREEN',
            confidence_score REAL DEFAULT 0.0,
            flags TEXT,
            metadata TEXT,
            ai_analysis TEXT,
            virustotal_result TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases(id)
        );

        CREATE TABLE IF NOT EXISTS timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            timestamp TIMESTAMP,
            event_type TEXT,
            description TEXT,
            source_file TEXT,
            severity TEXT DEFAULT 'GREEN',
            FOREIGN KEY (case_id) REFERENCES cases(id)
        );

        CREATE TABLE IF NOT EXISTS chain_of_custody (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            performed_by TEXT,
            details TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            details TEXT,
            case_id TEXT
        );
    ''')
    conn.commit()
    conn.close()


def log_audit(action, details, case_id=None):
    """Log an audit entry."""
    conn = get_db()
    conn.execute(
        'INSERT INTO audit_log (action, details, case_id) VALUES (?, ?, ?)',
        (action, details, case_id)
    )
    conn.commit()
    conn.close()


def log_chain_of_custody(case_id, action, performed_by, details):
    """Log a chain-of-custody entry."""
    conn = get_db()
    conn.execute(
        'INSERT INTO chain_of_custody (case_id, action, performed_by, details) VALUES (?, ?, ?, ?)',
        (case_id, action, performed_by, details)
    )
    conn.commit()
    conn.close()


def format_file_size(size_bytes):
    """Format file size to human-readable."""
    if size_bytes >= 1073741824:
        return f"{size_bytes / 1073741824:.1f} GB"
    elif size_bytes >= 1048576:
        return f"{size_bytes / 1048576:.1f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


# ─── Scan Engine ───
def run_scan(case_id, scan_target, officer_name):
    """
    Run a full forensic scan in a background thread.
    Steps: Scan → Hash → Analyze → Score → Timeline
    """
    active_scans[case_id] = {
        'status': 'scanning',
        'progress': 0,
        'total': 0,
        'current_file': '',
        'step': 'Device Scanning',
        'step_number': 1,
    }

    conn = get_db()

    try:
        # Step 1: Scan directory
        active_scans[case_id]['step'] = 'Scanning Files'
        active_scans[case_id]['step_number'] = 1
        conn.execute('UPDATE cases SET status = ? WHERE id = ?', ('scanning', case_id))
        conn.commit()

        log_chain_of_custody(case_id, 'Scan initiated', officer_name, f'Target: {scan_target}')

        scan_results = scan_directory(scan_target)
        files = scan_results['files']
        total_files = len(files)

        active_scans[case_id]['total'] = total_files

        # Step 2: Hash all files
        active_scans[case_id]['step'] = 'Computing File Hashes'
        active_scans[case_id]['step_number'] = 2

        for i, file_info in enumerate(files):
            sha256 = compute_sha256(file_info['file_path'])
            file_info['sha256_hash'] = sha256 or 'HASH_ERROR'
            active_scans[case_id]['progress'] = int((i + 1) / total_files * 33)
            active_scans[case_id]['current_file'] = file_info['file_name']

        # Step 3: Analyze files
        active_scans[case_id]['step'] = 'AI Analysis'
        active_scans[case_id]['step_number'] = 3

        gemini_model = get_gemini_client()
        for i, file_info in enumerate(files):
            if gemini_model:
                try:
                    file_info['ai_analysis'] = analyze_with_ai(file_info, gemini_model)
                except Exception:
                    file_info['ai_analysis'] = heuristic_analysis(file_info)
            else:
                file_info['ai_analysis'] = heuristic_analysis(file_info)

            active_scans[case_id]['progress'] = 33 + int((i + 1) / total_files * 33)
            active_scans[case_id]['current_file'] = file_info['file_name']

        # Step 4: Score and classify
        active_scans[case_id]['step'] = 'Classifying Evidence'
        active_scans[case_id]['step_number'] = 4

        red_count = 0
        amber_count = 0
        green_count = 0

        for i, file_info in enumerate(files):
            classification, confidence, flags = classify_file(file_info)
            file_info['classification'] = classification
            file_info['confidence_score'] = confidence
            file_info['flags'] = flags

            if classification == 'RED':
                red_count += 1
            elif classification == 'AMBER':
                amber_count += 1
            else:
                green_count += 1

            active_scans[case_id]['progress'] = 66 + int((i + 1) / total_files * 17)

        # Step 5: Generate timeline
        active_scans[case_id]['step'] = 'Generating Timeline'
        active_scans[case_id]['step_number'] = 5

        timeline_events = build_timeline(files)

        # Save to database
        for file_info in files:
            conn.execute('''
                INSERT INTO evidence (case_id, file_path, file_name, file_type, file_extension,
                    file_size, sha256_hash, classification, confidence_score, flags, ai_analysis)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                case_id,
                file_info.get('file_path', ''),
                file_info.get('file_name', ''),
                file_info.get('file_type', ''),
                file_info.get('file_extension', ''),
                file_info.get('file_size', 0),
                file_info.get('sha256_hash', ''),
                file_info.get('classification', 'GREEN'),
                file_info.get('confidence_score', 0.0),
                json.dumps(file_info.get('flags', [])),
                file_info.get('ai_analysis', ''),
            ))

        # Save timeline events
        for event in timeline_events[:200]:  # Limit stored events
            conn.execute('''
                INSERT INTO timeline (case_id, timestamp, event_type, description, source_file, severity)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                case_id,
                event.get('timestamp', ''),
                event.get('event_type', ''),
                event.get('description', ''),
                event.get('source_file', ''),
                event.get('severity', 'GREEN'),
            ))

        # Update case
        threat_level = get_overall_threat_level(red_count, amber_count, green_count)
        conn.execute('''
            UPDATE cases SET status = ?, threat_level = ?, total_files = ?,
                red_count = ?, amber_count = ?, green_count = ?, completed_at = ?
            WHERE id = ?
        ''', ('completed', threat_level, total_files, red_count, amber_count,
              green_count, datetime.now().isoformat(), case_id))

        conn.commit()

        log_chain_of_custody(case_id, 'Scan completed', officer_name,
            f'Files: {total_files}, RED: {red_count}, AMBER: {amber_count}, GREEN: {green_count}')
        log_audit('scan_completed', f'Case {case_id}: {total_files} files processed', case_id)

        active_scans[case_id]['status'] = 'completed'
        active_scans[case_id]['progress'] = 100
        active_scans[case_id]['step'] = 'Complete'

    except Exception as e:
        conn.execute('UPDATE cases SET status = ? WHERE id = ?', ('error', case_id))
        conn.commit()
        active_scans[case_id]['status'] = 'error'
        active_scans[case_id]['error'] = str(e)
        log_audit('scan_error', f'Case {case_id}: {str(e)}', case_id)
    finally:
        conn.close()


# ─── Routes ───

@app.route('/')
def dashboard():
    """Main dashboard — case overview and stats."""
    conn = get_db()
    cases = conn.execute('SELECT * FROM cases ORDER BY created_at DESC').fetchall()

    # Stats
    total_cases = len(cases)
    active_cases = sum(1 for c in cases if c['status'] in ('scanning', 'pending'))
    completed_cases = sum(1 for c in cases if c['status'] == 'completed')
    total_evidence = conn.execute('SELECT COUNT(*) FROM evidence').fetchone()[0]
    total_red = conn.execute('SELECT COUNT(*) FROM evidence WHERE classification = ?', ('RED',)).fetchone()[0]

    # Recent activity
    recent_audit = conn.execute('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 10').fetchall()

    conn.close()

    return render_template('dashboard.html',
        cases=cases,
        total_cases=total_cases,
        active_cases=active_cases,
        completed_cases=completed_cases,
        total_evidence=total_evidence,
        total_red=total_red,
        recent_audit=recent_audit,
        format_file_size=format_file_size,
    )


@app.route('/case/new', methods=['GET', 'POST'])
def new_case():
    """Create a new forensic case."""
    if request.method == 'POST':
        case_id = str(uuid.uuid4())[:8]
        case_name = request.form.get('case_name', 'Untitled Case')
        officer_name = request.form.get('officer_name', 'Unknown Officer')
        badge_number = request.form.get('badge_number', '')
        department = request.form.get('department', '')
        scan_target = request.form.get('scan_target', '')
        scan_type = request.form.get('scan_type', 'uploaded_folder')

        # Validate scan target
        if not os.path.exists(scan_target):
            flash('The specified path does not exist. Please check and try again.', 'error')
            return render_template('new_case.html')

        conn = get_db()
        conn.execute('''
            INSERT INTO cases (id, case_name, officer_name, badge_number, department, scan_target, scan_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (case_id, case_name, officer_name, badge_number, department, scan_target, scan_type))
        conn.commit()
        conn.close()

        log_audit('case_created', f'Case "{case_name}" created by {officer_name}', case_id)
        log_chain_of_custody(case_id, 'Case created', officer_name,
            f'Case: {case_name}, Target: {scan_target}, Type: {scan_type}')

        flash(f'Case "{case_name}" created successfully!', 'success')
        return redirect(url_for('case_detail', case_id=case_id))

    return render_template('new_case.html')


@app.route('/case/<case_id>')
def case_detail(case_id):
    """View case details, evidence, and scan progress."""
    conn = get_db()
    case = conn.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone()

    if not case:
        flash('Case not found.', 'error')
        return redirect(url_for('dashboard'))

    evidence = conn.execute(
        'SELECT * FROM evidence WHERE case_id = ? ORDER BY classification DESC, confidence_score DESC',
        (case_id,)
    ).fetchall()

    timeline_events = conn.execute(
        'SELECT * FROM timeline WHERE case_id = ? ORDER BY timestamp DESC LIMIT 50',
        (case_id,)
    ).fetchall()

    coc = conn.execute(
        'SELECT * FROM chain_of_custody WHERE case_id = ? ORDER BY timestamp DESC',
        (case_id,)
    ).fetchall()

    conn.close()

    scan_status = active_scans.get(case_id, None)
    threat_summary = get_threat_summary(
        case['red_count'] or 0, case['amber_count'] or 0, case['green_count'] or 0
    )

    return render_template('case_detail.html',
        case=case,
        evidence=evidence,
        timeline_events=timeline_events,
        chain_of_custody=coc,
        scan_status=scan_status,
        threat_summary=threat_summary,
        format_file_size=format_file_size,
    )


@app.route('/case/<case_id>/scan', methods=['POST'])
def start_scan(case_id):
    """Start a forensic scan for a case."""
    conn = get_db()
    case = conn.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone()
    conn.close()

    if not case:
        return jsonify({'error': 'Case not found'}), 404

    if case_id in active_scans and active_scans[case_id].get('status') == 'scanning':
        return jsonify({'error': 'Scan already in progress'}), 400

    # Start scan in background thread
    thread = threading.Thread(target=run_scan, args=(case_id, case['scan_target'], case['officer_name']))
    thread.daemon = True
    thread.start()

    return jsonify({'status': 'started', 'case_id': case_id})


@app.route('/case/<case_id>/scan/status')
def scan_status(case_id):
    """Get current scan progress."""
    status = active_scans.get(case_id, {'status': 'idle', 'progress': 0})
    return jsonify(status)


@app.route('/case/<case_id>/evidence')
def evidence_view(case_id):
    """View all evidence for a case."""
    conn = get_db()
    case = conn.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone()

    filter_class = request.args.get('filter', 'all')
    if filter_class == 'all':
        evidence = conn.execute(
            'SELECT * FROM evidence WHERE case_id = ? ORDER BY classification DESC, confidence_score DESC',
            (case_id,)
        ).fetchall()
    else:
        evidence = conn.execute(
            'SELECT * FROM evidence WHERE case_id = ? AND classification = ? ORDER BY confidence_score DESC',
            (case_id, filter_class.upper())
        ).fetchall()

    conn.close()

    return render_template('evidence.html',
        case=case,
        evidence=evidence,
        current_filter=filter_class,
        format_file_size=format_file_size,
    )


@app.route('/case/<case_id>/timeline')
def timeline_view(case_id):
    """View forensic timeline for a case."""
    conn = get_db()
    case = conn.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone()
    events = conn.execute(
        'SELECT * FROM timeline WHERE case_id = ? ORDER BY timestamp DESC LIMIT 200',
        (case_id,)
    ).fetchall()
    conn.close()

    return render_template('timeline.html', case=case, events=events)


@app.route('/case/<case_id>/report')
def report_view(case_id):
    """Preview report before downloading."""
    conn = get_db()
    case = conn.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone()
    evidence = conn.execute(
        'SELECT * FROM evidence WHERE case_id = ? ORDER BY classification DESC',
        (case_id,)
    ).fetchall()
    coc = conn.execute(
        'SELECT * FROM chain_of_custody WHERE case_id = ? ORDER BY timestamp',
        (case_id,)
    ).fetchall()
    conn.close()

    threat_summary = get_threat_summary(
        case['red_count'] or 0, case['amber_count'] or 0, case['green_count'] or 0
    )

    return render_template('report.html',
        case=case,
        evidence=evidence,
        chain_of_custody=coc,
        threat_summary=threat_summary,
        format_file_size=format_file_size,
    )


@app.route('/case/<case_id>/report/download')
def download_report(case_id):
    """Generate and download PDF report."""
    conn = get_db()
    case = dict(conn.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone())
    evidence = [dict(row) for row in conn.execute(
        'SELECT * FROM evidence WHERE case_id = ? ORDER BY classification DESC',
        (case_id,)
    ).fetchall()]
    timeline_events = [dict(row) for row in conn.execute(
        'SELECT * FROM timeline WHERE case_id = ? ORDER BY timestamp DESC LIMIT 50',
        (case_id,)
    ).fetchall()]
    coc = [dict(row) for row in conn.execute(
        'SELECT * FROM chain_of_custody WHERE case_id = ? ORDER BY timestamp',
        (case_id,)
    ).fetchall()]
    conn.close()

    # Generate PDF
    report_filename = f"forensic_report_{case_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    report_path = os.path.join(REPORTS_DIR, report_filename)

    generate_report(case, evidence, timeline_events, coc, report_path)

    log_audit('report_generated', f'PDF report generated for case {case_id}', case_id)
    log_chain_of_custody(case_id, 'Report generated', case.get('officer_name', 'System'),
        f'PDF report: {report_filename}')

    return send_file(report_path, as_attachment=True, download_name=report_filename)


@app.route('/case/<case_id>/delete', methods=['POST'])
def delete_case(case_id):
    """Delete a case and all associated data."""
    conn = get_db()
    case = conn.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone()
    if case:
        conn.execute('DELETE FROM evidence WHERE case_id = ?', (case_id,))
        conn.execute('DELETE FROM timeline WHERE case_id = ?', (case_id,))
        conn.execute('DELETE FROM chain_of_custody WHERE case_id = ?', (case_id,))
        conn.execute('DELETE FROM cases WHERE id = ?', (case_id,))
        conn.commit()
        log_audit('case_deleted', f'Case {case_id} deleted', case_id)
        flash('Case deleted successfully.', 'success')
    conn.close()
    return redirect(url_for('dashboard'))


# ─── Template Filters ───
@app.template_filter('format_size')
def format_size_filter(size):
    return format_file_size(size or 0)


@app.template_filter('format_datetime')
def format_datetime_filter(dt_str):
    if not dt_str:
        return 'N/A'
    try:
        dt = datetime.fromisoformat(str(dt_str))
        return dt.strftime('%b %d, %Y %I:%M %p')
    except (ValueError, TypeError):
        return str(dt_str)[:19]


@app.template_filter('parse_flags')
def parse_flags_filter(flags_str):
    if not flags_str:
        return []
    try:
        return json.loads(flags_str)
    except (json.JSONDecodeError, TypeError):
        return []


# ─── Main ───
if __name__ == '__main__':
    init_db()
    log_audit('system_start', 'Cyber Forensic Triage Software started')
    print("\n" + "="*60)
    print("  CYBER FORENSIC TRIAGE SOFTWARE")
    print("  AI-Powered Evidence Analysis")
    print("="*60)
    print(f"  Dashboard: http://127.0.0.1:5000")
    print(f"  Database:  {DB_PATH}")
    print("="*60 + "\n")
    app.run(debug=True, host='127.0.0.1', port=5000)
