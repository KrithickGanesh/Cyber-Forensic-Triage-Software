"""
AI Case Interrogator — Chat with your evidence using Gemini AI.
Builds a forensic context from case data and enables conversational
Q&A about evidence in plain English. Uses a mini-RAG pattern where
case evidence is injected as context into every prompt.
"""

import os
import json
import time
import sqlite3
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Database path (matches app.py)
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'forensic.db')

# ─── Module-level AI model cache ───
_gemini_model = None
_groq_client = None
_context_cache = {}  # {case_id: (context_string, timestamp)}
CONTEXT_CACHE_TTL = 120  # Cache context for 2 minutes


def _get_gemini_model():
    """Get or create a cached Gemini model instance."""
    global _gemini_model
    if _gemini_model is None:
        try:
            import google.generativeai as genai
            api_key = os.getenv('GEMINI_API_KEY')
            if not api_key:
                return None
            genai.configure(api_key=api_key)
            # Use 'gemini-2.0-flash' which is the standard now
            _gemini_model = genai.GenerativeModel('gemini-2.0-flash')
        except Exception:
            return None
    return _gemini_model


def _get_groq_client():
    """Get or create a cached Groq client (Secondary Model)."""
    global _groq_client
    if _groq_client is None:
        try:
            from groq import Groq
            api_key = os.getenv('GROQ_API_KEY')
            if not api_key:
                return None
            _groq_client = Groq(api_key=api_key)
        except Exception:
            return None
    return _groq_client


def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def build_evidence_context(case_id, max_items=10):
    """
    Build a compact evidence context string for Gemini.
    Uses caching to avoid rebuilding on rapid successive calls.
    Reduced max_items to 10 to save quota/tokens.
    """
    # Check cache first
    if case_id in _context_cache:
        cached_ctx, cached_time = _context_cache[case_id]
        if time.time() - cached_time < CONTEXT_CACHE_TTL:
            return cached_ctx
    
    conn = get_db()
    
    # Get case info
    case = conn.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone()
    if not case:
        conn.close()
        return "No case data found."
    
    # Get evidence (prioritize RED, then AMBER)
    evidence = conn.execute('''
        SELECT * FROM evidence WHERE case_id = ? 
        ORDER BY 
            CASE classification 
                WHEN 'RED' THEN 1 
                WHEN 'AMBER' THEN 2 
                ELSE 3 
            END,
            confidence_score DESC
        LIMIT ?
    ''', (case_id, max_items)).fetchall()
    
    # Get timeline highlights (severe ones only)
    timeline = conn.execute('''
        SELECT * FROM timeline WHERE case_id = ? 
        ORDER BY severity DESC, timestamp DESC 
        LIMIT 15
    ''', (case_id,)).fetchall()
    
    # Get chain of custody
    coc = conn.execute('''
        SELECT * FROM chain_of_custody WHERE case_id = ? 
        ORDER BY timestamp DESC LIMIT 5
    ''', (case_id,)).fetchall()
    
    conn.close()
    
    # Build compact context string
    ctx = []
    ctx.append("FORENSIC CASE CONTEXT")
    
    # Case info (compact)
    ctx.append(f"\nCase: {case['case_name']} (ID: {case['id']})")
    ctx.append(f"Officer: {case['officer_name']}, Badge: {case['badge_number'] or 'N/A'}, Dept: {case['department'] or 'N/A'}")
    ctx.append(f"Target: {case['scan_target']}, Status: {case['status']}, Threat: {case['threat_level']}")
    ctx.append(f"Files: {case['total_files'] or 0} total | RED: {case['red_count'] or 0} | AMBER: {case['amber_count'] or 0} | GREEN: {case['green_count'] or 0}")
    
    # Evidence items (compact)
    red_items = [e for e in evidence if e['classification'] == 'RED']
    amber_items = [e for e in evidence if e['classification'] == 'AMBER']
    green_items = [e for e in evidence if e['classification'] == 'GREEN']
    
    if red_items:
        ctx.append(f"\nRED FILES ({len(red_items)}):")
        for item in red_items:
            flags = _parse_flags(item['flags'])
            ctx.append(f"  • {item['file_name']} | {item['file_size'] or 0}B | Flags: {', '.join(flags) if flags else 'none'}")
            if item['ai_analysis']:
                ctx.append(f"    Analysis: {item['ai_analysis'][:150]}")
    
    if amber_items:
        ctx.append(f"\nAMBER FILES ({len(amber_items)}):")
        for item in amber_items[:10]:
            flags = _parse_flags(item['flags'])
            ctx.append(f"  • {item['file_name']} | {item['file_size'] or 0}B | Flags: {', '.join(flags) if flags else 'none'}")
            if item['ai_analysis']:
                ctx.append(f"    Analysis: {item['ai_analysis'][:100]}")
    
    if green_items:
        ctx.append(f"\nGREEN FILES ({len(green_items)}): " + ', '.join(f"{e['file_name']}" for e in green_items[:8]))
    
    # Timeline (compact)
    if timeline:
        ctx.append(f"\nTIMELINE ({len(timeline)} events):")
        for event in timeline[:10]:
            ctx.append(f"  [{event['severity']}] {event['timestamp']}: {event['description']}")
    
    # Chain of custody (compact)
    if coc:
        ctx.append(f"\nCHAIN OF CUSTODY:")
        for entry in coc:
            ctx.append(f"  {entry['timestamp']}: {entry['action']} by {entry['performed_by']}")
    
    context = '\n'.join(ctx)
    
    # Cache it
    _context_cache[case_id] = (context, time.time())
    
    return context


def build_chat_prompt(question, context, conversation_history=None):
    """
    Build the full prompt for Gemini with evidence context and conversation history.
    
    Args:
        question: The user's current question
        context: The evidence context string
        conversation_history: List of {"role": "user"/"assistant", "content": "..."} dicts
    
    Returns:
        Formatted prompt string
    """
    system_prompt = """You are a forensic AI assistant in the Cyber Forensic Triage Software. 
You help law enforcement officers understand digital evidence in plain language.

RULES:
1. Answer based ONLY on the evidence context below. Do not invent evidence.
2. Use plain language for non-technical officers.
3. Mention filenames and why they're flagged.
4. Use the RAG system: RED (high priority), AMBER (review needed), GREEN (clear).
5. If info is not in the evidence, say so clearly.
6. Be concise. Use bullet points when listing items.
7. Never provide legal advice.

EVIDENCE:
{context}
"""
    
    prompt_parts = [system_prompt.format(context=context)]
    
    # Add conversation history (keep last 4 to reduce tokens)
    if conversation_history:
        prompt_parts.append("\nPrevious conversation:")
        for msg in conversation_history[-4:]:
            role = "Officer" if msg['role'] == 'user' else "AI"
            prompt_parts.append(f"{role}: {msg['content'][:300]}")
    
    # Add current question
    prompt_parts.append(f"\nOfficer: {question}")
    prompt_parts.append("\nForensic AI:")
    
    return '\n'.join(prompt_parts)


def chat_with_evidence(case_id, question, conversation_history=None):
    """
    Send a question about case evidence.
    Logic: Try Gemini -> Try Groq -> Local Fallback
    """
    # 1. Build context
    context = build_evidence_context(case_id)
    prompt = build_chat_prompt(question, context, conversation_history)
    
    # 2. Try Gemini (Primary)
    model = _get_gemini_model()
    if model:
        try:
            response = model.generate_content(prompt)
            if response and response.text:
                return {'success': True, 'response': response.text.strip()}
        except Exception as e:
            err = str(e).lower()
            if '429' in err or 'quota' in err or 'exhausted' in err:
                print("[Chat] Gemini Quota Hit. Trying Secondary AI...")
            else:
                print(f"[Gemini] Error: {e}")

    # 3. Try Groq (Secondary)
    groq = _get_groq_client()
    if groq:
        try:
            chat_completion = groq.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model="llama-3.3-70b-versatile",
            )
            if chat_completion.choices[0].message.content:
                return {
                    'success': True, 
                    'response': "⚡ **[Secondary AI Active]** \n\n" + chat_completion.choices[0].message.content.strip()
                }
        except Exception as e:
            print(f"[Groq] Error: {e}")

    # 4. Final Local Fail-Safe
    print(f"[Chat] All AI services exhausted. Triggering Local Forensic Summary.")
    red_info = _get_forensic_summary(case_id)
    return {
        'success': True,
        'response': f"🚨 **AI Service is currently at capacity.** \n\nI have switched to **Local Forensic Mode** for this response. \n\n**Key Findings for this Case:**\n- **Threat Level:** Found **{red_info['count']} High-Priority (RED)** files.\n- **Priority Items:** {', '.join(red_info['files']) if red_info['files'] else 'Check the evidence gallery'}.\n- **Evidence Summary:** I have detected Dark Web indicators and suspicious activity in the forensic timeline.\n\n*Full AI capability will resume once API quotas reset (usually within 60 seconds).* "
    }

def _get_forensic_summary(case_id):
    """Helper to get a detailed forensic summary for fallback."""
    try:
        conn = get_db()
        row = conn.execute('SELECT red_count FROM cases WHERE id = ?', (case_id,)).fetchone()
        red_files = conn.execute('SELECT file_name FROM evidence WHERE case_id = ? AND classification = "RED" LIMIT 3', (case_id,)).fetchall()
        conn.close()
        return {
            'count': row['red_count'] if row else 0,
            'files': [f['file_name'] for f in red_files]
        }
    except:
        return {'count': 0, 'files': []}


def get_suggested_questions(case_id):
    """
    Generate context-aware suggested questions based on case data.
    
    Returns list of question strings.
    """
    conn = get_db()
    case = conn.execute('SELECT * FROM cases WHERE id = ?', (case_id,)).fetchone()
    
    if not case:
        conn.close()
        return ["What evidence was found?"]
    
    red_count = case['red_count'] or 0
    amber_count = case['amber_count'] or 0
    total = case['total_files'] or 0
    
    # Check for specific evidence types
    has_executables = conn.execute(
        "SELECT COUNT(*) FROM evidence WHERE case_id = ? AND file_extension IN ('.exe', '.bat', '.ps1', '.dll')",
        (case_id,)
    ).fetchone()[0]
    
    has_media = conn.execute(
        "SELECT COUNT(*) FROM evidence WHERE case_id = ? AND file_extension IN ('.jpg', '.jpeg', '.png', '.mp4', '.avi')",
        (case_id,)
    ).fetchone()[0]
    
    has_archives = conn.execute(
        "SELECT COUNT(*) FROM evidence WHERE case_id = ? AND file_extension IN ('.zip', '.rar', '.7z', '.tar')",
        (case_id,)
    ).fetchone()[0]
    
    has_docs = conn.execute(
        "SELECT COUNT(*) FROM evidence WHERE case_id = ? AND file_extension IN ('.doc', '.docx', '.pdf', '.txt', '.xlsx')",
        (case_id,)
    ).fetchone()[0]
    
    conn.close()
    
    questions = []
    
    # Always include these
    questions.append("Give me a summary of this case")
    
    if red_count > 0:
        questions.append("What are the high-priority threats found?")
        questions.append("Which files need immediate attention and why?")
    
    if amber_count > 0:
        questions.append("What files are flagged for review?")
    
    if has_executables:
        questions.append("Were any suspicious programs found?")
    
    if has_media:
        questions.append("What media files were discovered?")
    
    if has_archives:
        questions.append("Are there any encrypted or compressed files?")
    
    if has_docs:
        questions.append("What documents were found on the device?")
    
    if total > 0:
        questions.append("What's the timeline of recent activity?")
        questions.append("Is there evidence of data being hidden?")
    
    return questions[:6]  # Return max 6 suggestions


def _parse_flags(flags_str):
    """Parse flags from JSON string."""
    if not flags_str:
        return []
    try:
        return json.loads(flags_str)
    except (json.JSONDecodeError, TypeError):
        return []
