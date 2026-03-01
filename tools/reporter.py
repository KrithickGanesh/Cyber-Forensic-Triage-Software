"""
Reporter — Court-ready PDF report generation using ReportLab.
Generates professional forensic triage reports with case details,
evidence tables, timeline, and chain-of-custody documentation.
"""

import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Image
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


# RAG colors for ReportLab
RAG_COLORS = {
    'RED': colors.Color(0.94, 0.27, 0.27),
    'AMBER': colors.Color(0.96, 0.62, 0.04),
    'GREEN': colors.Color(0.13, 0.77, 0.37),
}


def generate_report(case_data, evidence_items, timeline_events, chain_of_custody, output_path):
    """
    Generate a court-ready PDF report.
    
    Args:
        case_data: Dict with case information
        evidence_items: List of evidence item dicts
        timeline_events: List of timeline event dicts
        chain_of_custody: List of chain-of-custody entries
        output_path: Path to save the PDF
    
    Returns:
        Path to generated PDF
    """
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=25*mm,
        bottomMargin=25*mm,
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    styles.add(ParagraphStyle(
        'ReportTitle',
        parent=styles['Title'],
        fontSize=22,
        spaceAfter=6,
        textColor=colors.Color(0.1, 0.1, 0.15),
        fontName='Helvetica-Bold',
    ))
    
    styles.add(ParagraphStyle(
        'ReportSubtitle',
        parent=styles['Normal'],
        fontSize=11,
        spaceAfter=20,
        textColor=colors.Color(0.4, 0.4, 0.45),
        alignment=TA_CENTER,
    ))
    
    styles.add(ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading2'],
        fontSize=14,
        spaceBefore=20,
        spaceAfter=10,
        textColor=colors.Color(0.1, 0.1, 0.15),
        borderPadding=(0, 0, 5, 0),
    ))
    
    styles.add(ParagraphStyle(
        'FieldLabel',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.Color(0.5, 0.5, 0.55),
    ))
    
    styles.add(ParagraphStyle(
        'FieldValue',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.Color(0.1, 0.1, 0.15),
        spaceAfter=8,
    ))
    
    elements = []
    
    # ─── HEADER ───
    elements.append(Paragraph("CYBER FORENSIC TRIAGE REPORT", styles['ReportTitle']))
    elements.append(Paragraph("DIGITAL EVIDENCE ANALYSIS — CONFIDENTIAL", styles['ReportSubtitle']))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.Color(0.0, 0.83, 1.0)))
    elements.append(Spacer(1, 15))
    
    # ─── CASE INFORMATION ───
    elements.append(Paragraph("Case Information", styles['SectionTitle']))
    
    case_info_data = [
        ['Case ID:', case_data.get('id', 'N/A'), 'Case Name:', case_data.get('case_name', 'N/A')],
        ['Officer:', case_data.get('officer_name', 'N/A'), 'Badge #:', case_data.get('badge_number', 'N/A')],
        ['Department:', case_data.get('department', 'N/A'), 'Date:', case_data.get('created_at', 'N/A')],
        ['Scan Target:', case_data.get('scan_target', 'N/A'), 'Scan Type:', case_data.get('scan_type', 'N/A')],
    ]
    
    case_table = Table(case_info_data, colWidths=[80, 170, 70, 170])
    case_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.Color(0.4, 0.4, 0.45)),
        ('TEXTCOLOR', (2, 0), (2, -1), colors.Color(0.4, 0.4, 0.45)),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(case_table)
    elements.append(Spacer(1, 15))
    
    # ─── EXECUTIVE SUMMARY ───
    elements.append(Paragraph("Executive Summary", styles['SectionTitle']))
    
    red_count = case_data.get('red_count', 0)
    amber_count = case_data.get('amber_count', 0)
    green_count = case_data.get('green_count', 0)
    total = case_data.get('total_files', 0)
    threat_level = case_data.get('threat_level', 'GREEN')
    
    threat_color = RAG_COLORS.get(threat_level, colors.grey)
    
    summary_data = [
        ['Overall Threat Level', 'Total Files', 'High Priority (Red)', 'Review (Amber)', 'Clear (Green)'],
        [threat_level, str(total), str(red_count), str(amber_count), str(green_count)],
    ]
    
    summary_table = Table(summary_data, colWidths=[100, 90, 100, 100, 100])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.95, 0.95, 0.97)),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.85, 0.85, 0.88)),
        ('TEXTCOLOR', (0, 1), (0, 1), threat_color),
        ('FONTNAME', (0, 1), (0, 1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (2, 1), (2, 1), RAG_COLORS['RED']),
        ('TEXTCOLOR', (3, 1), (3, 1), RAG_COLORS['AMBER']),
        ('TEXTCOLOR', (4, 1), (4, 1), RAG_COLORS['GREEN']),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 15))
    
    # ─── EVIDENCE TABLE ───
    elements.append(Paragraph("Evidence Items", styles['SectionTitle']))
    
    if evidence_items:
        # Header
        ev_header = ['#', 'File Name', 'Type', 'Size', 'Priority', 'SHA-256 (first 16)']
        ev_data = [ev_header]
        
        for i, item in enumerate(evidence_items[:50], 1):  # limit to 50 for PDF
            size = item.get('file_size', 0)
            if size > 1024 * 1024:
                size_str = f"{size / (1024*1024):.1f} MB"
            elif size > 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} B"
            
            sha = item.get('sha256_hash', 'N/A')
            sha_short = sha[:16] + '...' if sha and sha != 'N/A' else 'N/A'
            
            ev_data.append([
                str(i),
                item.get('file_name', 'Unknown')[:30],
                item.get('file_extension', 'N/A'),
                size_str,
                item.get('classification', 'GREEN'),
                sha_short,
            ])
        
        ev_table = Table(ev_data, colWidths=[25, 140, 45, 60, 55, 120])
        
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.1, 0.1, 0.15)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.88, 0.88, 0.9)),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.97, 0.97, 0.99)]),
        ]
        
        # Color-code the Priority column
        for i, item in enumerate(evidence_items[:50], 1):
            classification = item.get('classification', 'GREEN')
            color = RAG_COLORS.get(classification, colors.grey)
            table_style.append(('TEXTCOLOR', (4, i), (4, i), color))
            table_style.append(('FONTNAME', (4, i), (4, i), 'Helvetica-Bold'))
        
        ev_table.setStyle(TableStyle(table_style))
        elements.append(ev_table)
    else:
        elements.append(Paragraph("No evidence items found.", styles['Normal']))
    
    elements.append(Spacer(1, 15))
    
    # ─── TIMELINE ───
    if timeline_events:
        elements.append(PageBreak())
        elements.append(Paragraph("Event Timeline", styles['SectionTitle']))
        
        tl_header = ['Time', 'Event', 'File', 'Priority']
        tl_data = [tl_header]
        
        for event in timeline_events[:30]:
            try:
                ts = datetime.fromisoformat(event['timestamp'])
                time_str = ts.strftime('%Y-%m-%d %H:%M')
            except (ValueError, TypeError):
                time_str = str(event.get('timestamp', 'N/A'))
            
            tl_data.append([
                time_str,
                event.get('event_type', '').replace('_', ' ').title(),
                event.get('source_file', 'N/A')[:35],
                event.get('severity', 'GREEN'),
            ])
        
        tl_table = Table(tl_data, colWidths=[100, 100, 180, 55])
        tl_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.1, 0.1, 0.15)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.88, 0.88, 0.9)),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.Color(0.97, 0.97, 0.99)]),
        ]))
        elements.append(tl_table)
    
    # ─── CHAIN OF CUSTODY ───
    if chain_of_custody:
        elements.append(Spacer(1, 20))
        elements.append(Paragraph("Chain of Custody", styles['SectionTitle']))
        
        coc_header = ['Timestamp', 'Action', 'Performed By', 'Details']
        coc_data = [coc_header]
        
        for entry in chain_of_custody:
            coc_data.append([
                str(entry.get('timestamp', 'N/A'))[:19],
                entry.get('action', 'N/A'),
                entry.get('performed_by', 'N/A'),
                str(entry.get('details', 'N/A'))[:50],
            ])
        
        coc_table = Table(coc_data, colWidths=[110, 100, 100, 135])
        coc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.1, 0.1, 0.15)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.Color(0.88, 0.88, 0.9)),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(coc_table)
    
    # ─── FOOTER ───
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.Color(0.8, 0.8, 0.85)))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(
        f"Report generated by Cyber Forensic Triage Software on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.Color(0.5, 0.5, 0.55), alignment=TA_CENTER)
    ))
    elements.append(Paragraph(
        "This document is generated for law enforcement purposes. Handle according to department evidence protocols.",
        ParagraphStyle('FooterNote', parent=styles['Normal'], fontSize=7, textColor=colors.Color(0.6, 0.6, 0.65), alignment=TA_CENTER)
    ))
    
    doc.build(elements)
    return output_path
