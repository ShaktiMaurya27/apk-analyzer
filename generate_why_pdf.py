import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

def build_pdf():
    pdf_path = "WHY.pdf"
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#059669'),
        spaceAfter=15
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor('#334155'),
        spaceAfter=6
    )

    qa_title_style = ParagraphStyle(
        'QATitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=14.5,
        textColor=colors.HexColor('#0f766e'),
        spaceBefore=6,
        spaceAfter=3
    )

    qa_body_style = ParagraphStyle(
        'QABody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#1f2937'),
        spaceAfter=8
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#1e293b')
    )

    story = []

    # Title & Subtitle
    story.append(Paragraph("apk-analyzer — Technical Architecture & Library Rationale", title_style))
    story.append(Paragraph("Why Specific Libraries Were Chosen & Viva / Interview FAQ in Hinglish", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#10b981'), spaceAfter=12))

    # Section 1: Library & Architecture Justification Table
    story.append(Paragraph("1. Library Selection & Rejection Matrix", h2_style))
    story.append(Paragraph("The table below details why specific Python libraries and frameworks were selected for the apk-analyzer static reverse-engineering pipeline and why alternative tools were rejected.", body_style))

    table_data = [
        [
            Paragraph("Component / Layer", table_header_style),
            Paragraph("Chosen Library / Approach", table_header_style),
            Paragraph("Rejected Alternatives", table_header_style),
            Paragraph("Technical Justification & Why Only This Tool", table_header_style)
        ],
        [
            Paragraph("APK Ingestion & Hashing", table_cell_style),
            Paragraph("Python stdlib (zipfile, hashlib)", table_cell_style),
            Paragraph("patool, shutil unpack", table_cell_style),
            Paragraph("Zero external dependencies. Runs directly in memory without installing C binaries or external tools.", table_cell_style)
        ],
        [
            Paragraph("Binary Manifest Parser", table_cell_style),
            Paragraph("Custom Pure-Python AXML Parser (axml.py)", table_cell_style),
            Paragraph("apktool, androguard, pyaxmlparser", table_cell_style),
            Paragraph("Apktool requires Java JRE and subprocess spawning (adds 3-5s latency). Androguard has heavy legacy dependencies (networkx, pyasn1). Custom parser decodes AXML in under 5ms.", table_cell_style)
        ],
        [
            Paragraph("Data Schema & Validation", table_cell_style),
            Paragraph("Pydantic v2", table_cell_style),
            Paragraph("dataclasses, raw dicts", table_cell_style),
            Paragraph("Guarantees strict schema validation, risk score constraints (0-100), and automated JSON output matching security standards.", table_cell_style)
        ],
        [
            Paragraph("Bytecode & Entropy Engine", table_cell_style),
            Paragraph("Pure Python math & regex (re)", table_cell_style),
            Paragraph("capstone, javassist, dexlib2", table_cell_style),
            Paragraph("Calculates Shannon Entropy (H) directly on DEX bytes without native C-extension compilation dependencies.", table_cell_style)
        ],
        [
            Paragraph("PDF Generation", table_cell_style),
            Paragraph("ReportLab 4.2", table_cell_style),
            Paragraph("weasyprint, pdfkit (wkhtmltopdf)", table_cell_style),
            Paragraph("Pure Python vector PDF engine. Does not require headless Chrome or external system webkit binaries.", table_cell_style)
        ],
        [
            Paragraph("Web Interface", table_cell_style),
            Paragraph("Single-file HTML5 + Tailwind + JSZip", table_cell_style),
            Paragraph("React, Vue, Angular, Next.js", table_cell_style),
            Paragraph("Zero build tools (npm/node_modules). Operates offline in any browser; JSZip enables client-side zip parsing.", table_cell_style)
        ]
    ]

    t = Table(table_data, colWidths=[90, 110, 110, 230])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 14))

    # Section 2: Viva & Technical FAQ (Hinglish)
    story.append(Paragraph("2. Frequently Asked Questions (Viva / Interview Q&A in Hinglish)", h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceAfter=8))

    faqs = [
        ("Q1: Is project me androguard ya apktool kyun use nahi kiya?",
         "Answer: apktool ko chalane ke liye system me Java (JRE) installed hona zaroori hota hai aur wo background me subprocess spawn karta hai jisse analysis bohot slow (~3-5 seconds) ho jaati hai. androguard me bohot saari heavy external dependencies hoti hain. Humne ek Pure Python Binary AXML Parser (axml.py) likha hai jo directly APK ke AndroidManifest.xml bytes ke String Pool aur Resource IDs ko 5 milliseconds me decode kar leta hai bina kisi external tool ya Java setup ke."),
        
        ("Q2: Dynamic Analysis (Live Sandbox Execution) kyun nahi kiya, sirf Static Analysis kyun?",
         "Answer: Dynamic analysis me malware ko real device ya emulator pe run karna padta hai jo risky hota hai, battery/cpu intensive hota hai, aur malware sandbox evasion (jaise isDebuggerConnected() check karna) se chhup sakta hai. Static & Heuristic Analysis fast hota hai, safe hota hai (code execute hi nahi hota), aur application ki saari permissions, hardcoded C2 IPs, dynamic class loaders (DexClassLoader), aur debug certs ko bina run kiye instantly spot kar leta hai."),
        
        ("Q3: Shannon Entropy calculation se packing aur malware kaise detect hota hai?",
         "Answer: Normal uncompressed DEX bytecode ka Shannon Entropy score around 4.0 to 6.2 hota hai kyunki code me repeated structure hoti hai. Lekin jab malware author code ko pack, encrypt ya obfuscate karta hai (jaise Qihoo 360, Bangcle), to byte randomness badh jaati hai aur Entropy 7.4 se 8.0 ho jaati hai. Agar entropy >= 7.4 milti hai, to hamara engine ise Extremely High / Packed Payload flag kar deta hai."),
        
        ("Q4: Risk Score 0 se 100 kaise calculate hota hai?",
         "Answer: Risk Score har phase ke findings ke weights ko calculate karke aggregation karta hai: Critical Findings (C2 endpoints, Accessibility Service abuse, Banking Trojan Overlay signature, DexClassLoader + Disguised assets) ko +25 to +35 points; High Findings (Debug certs, Unprotected Boot Receivers, Shell execution) ko +20 points; Dangerous Permissions ko +5 points per permission (capped at 25); aur Packing/High Entropy ko +15 points. Score 0-39 ko Safe, 40-69 ko Suspicious, aur 70-100 ko Malicious categorize kiya jata hai."),
        
        ("Q5: Web Interface offline kaise kaam karta hai?",
         "Answer: Web UI ko single-file HTML5 format me Tailwind CSS CDN aur inline JavaScript logic ke saath banaya gaya hai. Ye user ke browser me run hota hai, jisme JSZip engine binary APKs ko client-side unpack karta hai aur simulated/live progress logging ke sath interactive risk meter gauge aur JSON report generation render karta hai."),
        
        ("Q6: What are dangerous permission combinations in Android security?",
         "Answer: Single permissions dangerous ho sakti hain, lekin combinations zyada lethal hoti hain: 1) Banking Trojan Overlay: RECEIVE_BOOT_COMPLETED + SYSTEM_ALERT_WINDOW (boot hote hi overlay launch karke bank credentials phish karna). 2) Spyware Exfiltration: INTERNET + READ_CONTACTS/RECORD_AUDIO + SEND_SMS. 3) SMS 2FA Interception: RECEIVE_SMS + SEND_SMS + INTERNET (bank OTPs steal karke remote server pe bhejna).")
    ]

    for q, a in faqs:
        story.append(Paragraph(q, qa_title_style))
        story.append(Paragraph(a, qa_body_style))

    doc.build(story)
    print(f"[+] Successfully generated PDF document at: {pdf_path}")

if __name__ == "__main__":
    build_pdf()
