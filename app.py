import streamlit as st
import pandas as pd
from datetime import datetime, timedelta, timezone
import re

import api_checks
from backend import analyze_job, extract_text_from_image
from feedback_storage import save_feedback

# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="SCAMSHIELD",
    page_icon="🛡️",
    layout="wide"
)

# =====================================================
# SESSION STATE — statistics
# =====================================================

if "total_scans" not in st.session_state:
    st.session_state.total_scans = 0
if "scams_caught" not in st.session_state:
    st.session_state.scams_caught = 0
if "legit_jobs" not in st.session_state:
    st.session_state.legit_jobs = 0
if "suspicious_jobs" not in st.session_state:
    st.session_state.suspicious_jobs = 0

# =====================================================
# CSS — adaptive light/dark mode
# =====================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Inter:wght@300;400;500;600;700&display=swap');

/* ---- ROOT VARIABLES (dark default) ---- */
:root {
    --bg-primary: #0F172A;
    --bg-secondary: #1E293B;
    --bg-tertiary: #334155;
    --text-primary: #F8FAFC;
    --text-secondary: #CBD5E1;
    --accent: #38BDF8;
    --accent-glow: rgba(56,189,248,0.15);
    --border: #334155;
    --safe-bg: #064E3B;
    --safe-text: #D1FAE5;
    --warn-bg: #78350F;
    --warn-text: #FEF3C7;
    --danger-bg: #7F1D1D;
    --danger-text: #FEE2E2;
    --highlight-color: rgba(251, 191, 36, 0.35);
    --tag-bg: #1E3A5F;
    --tag-text: #93C5FD;
}

/* ---- LIGHT MODE OVERRIDE ---- */
@media (prefers-color-scheme: light) {
    :root {
        --bg-primary: #F1F5F9;
        --bg-secondary: #FFFFFF;
        --bg-tertiary: #E2E8F0;
        --text-primary: #0F172A;
        --text-secondary: #475569;
        --accent: #0284C7;
        --accent-glow: rgba(2,132,199,0.10);
        --border: #CBD5E1;
        --safe-bg: #DCFCE7;
        --safe-text: #14532D;
        --warn-bg: #FEF9C3;
        --warn-text: #713F12;
        --danger-bg: #FEE2E2;
        --danger-text: #7F1D1D;
        --highlight-color: rgba(234, 179, 8, 0.30);
        --tag-bg: #DBEAFE;
        --tag-text: #1D4ED8;
    }
}

/* ---- BASE ---- */
.stApp {
    background-color: var(--bg-primary) !important;
    color: var(--text-primary) !important;
    font-family: 'Inter', sans-serif;
}

/* ---- HEADER ---- */
.shield-header {
    text-align: center;
    padding: 30px 0 10px 0;
}
.shield-title {
    font-family: 'Space Mono', monospace;
    font-size: 52px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: 6px;
    text-shadow: 0 0 30px var(--accent-glow);
    margin: 0;
}
.shield-subtitle {
    font-size: 15px;
    color: var(--text-secondary);
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-top: 6px;
}

/* ---- STAT BADGES (top right) ---- */
.stat-bar {
    display: flex;
    gap: 10px;
    justify-content: flex-end;
    flex-wrap: wrap;
    margin-bottom: 10px;
}
.stat-badge {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 6px 14px;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
}
.stat-badge.scam { border-color: #EF4444; color: #EF4444; }
.stat-badge.legit { border-color: #22C55E; color: #22C55E; }
.stat-badge.suspicious { border-color: #F59E0B; color: #F59E0B; }
.stat-badge.total { border-color: var(--accent); color: var(--accent); }

/* ---- TIME BOX ---- */
.time-box {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px 18px;
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 16px;
    font-family: 'Space Mono', monospace;
}

/* ---- BOXES ---- */
.box {
    background: var(--bg-secondary);
    padding: 20px;
    border-radius: 14px;
    border: 1px solid var(--border);
    margin-bottom: 18px;
    color: var(--text-primary);
}

/* ---- VERDICT BANNERS ---- */
.verdict-safe {
    background: var(--safe-bg);
    color: var(--safe-text);
    padding: 20px 24px;
    border-radius: 12px;
    font-size: 22px;
    font-weight: 700;
    font-family: 'Space Mono', monospace;
    letter-spacing: 2px;
    display: flex;
    align-items: center;
    gap: 12px;
}
.verdict-warning {
    background: var(--warn-bg);
    color: var(--warn-text);
    padding: 20px 24px;
    border-radius: 12px;
    font-size: 22px;
    font-weight: 700;
    font-family: 'Space Mono', monospace;
    letter-spacing: 2px;
    display: flex;
    align-items: center;
    gap: 12px;
}
.verdict-danger {
    background: var(--danger-bg);
    color: var(--danger-text);
    padding: 20px 24px;
    border-radius: 12px;
    font-size: 22px;
    font-weight: 700;
    font-family: 'Space Mono', monospace;
    letter-spacing: 2px;
    display: flex;
    align-items: center;
    gap: 12px;
}

/* ---- GAUGE ---- */
.gauge-wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 20px;
    background: var(--bg-secondary);
    border-radius: 14px;
    border: 1px solid var(--border);
}
.gauge-label {
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 8px;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.gauge-score {
    font-family: 'Space Mono', monospace;
    font-size: 40px;
    font-weight: 700;
    color: var(--accent);
}
.gauge-sub {
    font-size: 12px;
    color: var(--text-secondary);
    margin-top: 4px;
}

/* ---- RISK BAR ---- */
.risk-bar-wrap {
    background: var(--bg-secondary);
    border-radius: 14px;
    border: 1px solid var(--border);
    padding: 20px;
}
.risk-bar-label {
    display: flex;
    justify-content: space-between;
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 6px;
}
.risk-bar-outer {
    background: var(--bg-tertiary);
    border-radius: 999px;
    height: 10px;
    margin-bottom: 14px;
    overflow: hidden;
}
.risk-bar-inner {
    height: 10px;
    border-radius: 999px;
    transition: width 0.6s ease;
}

/* ---- HIGHLIGHTED TEXT ---- */
.highlighted-text {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px;
    line-height: 2;
    font-size: 14px;
    color: var(--text-primary);
    white-space: pre-wrap;
    word-break: break-word;
}
mark.scam-highlight {
    background: var(--highlight-color);
    color: var(--text-primary);
    border-radius: 4px;
    padding: 1px 3px;
    font-weight: 600;
    border-bottom: 2px solid #F59E0B;
}

/* ---- SCAM TYPE TAG ---- */
.scam-type-tag {
    display: inline-block;
    background: var(--tag-bg);
    color: var(--tag-text);
    border-radius: 20px;
    padding: 4px 14px;
    font-size: 13px;
    font-weight: 600;
    margin: 4px 4px 4px 0;
    border: 1px solid var(--accent);
}

/* ---- EMAIL / PHONE BOX ---- */
.info-box {
    background: var(--bg-secondary);
    border-left: 3px solid var(--accent);
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 12px;
    color: var(--text-primary);
}
.info-box .label {
    font-size: 11px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1px;
}
.info-box .value {
    font-size: 15px;
    font-weight: 600;
    margin-top: 2px;
}

/* ---- SIDEBAR ---- */
section[data-testid="stSidebar"] {
    background-color: var(--bg-secondary) !important;
}
section[data-testid="stSidebar"] * {
    color: var(--text-primary) !important;
}

/* ---- INPUTS ---- */
.stTextArea textarea,
.stTextInput input {
    background-color: var(--bg-secondary) !important;
    color: var(--text-primary) !important;
    border-color: var(--border) !important;
}

/* ---- BUTTONS ---- */
.stButton > button {
    background: var(--accent) !important;
    color: #0F172A !important;
    font-weight: 700 !important;
    border: none !important;
    border-radius: 8px !important;
}

/* ---- SECTION HEADERS ---- */
.section-header {
    font-family: 'Space Mono', monospace;
    font-size: 16px;
    color: var(--accent);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin: 24px 0 12px 0;
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
}

/* ---- REASON ITEM ---- */
.reason-item {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 14px;
    background: var(--bg-secondary);
    border-radius: 8px;
    margin-bottom: 8px;
    font-size: 14px;
    color: var(--text-primary);
    border-left: 3px solid var(--accent);
}

</style>
""", unsafe_allow_html=True)

# =====================================================
# IST TIME
# =====================================================

def get_ist_time():
    ist = timezone(timedelta(hours=5, minutes=30))
    return datetime.now(ist).strftime("%d %B %Y | %I:%M:%S %p IST")

# =====================================================
# TEXT HIGHLIGHTER
# =====================================================

def highlight_text(text, keywords):
    """Highlights scam keywords in the extracted text."""
    if not keywords or not text:
        return text
    highlighted = text
    for kw_entry in keywords:
        phrase = kw_entry.split(" — ")[0].strip()
        pattern = re.compile(re.escape(phrase), re.IGNORECASE)
        highlighted = pattern.sub(
            lambda m: f'<mark class="scam-highlight">{m.group()}</mark>',
            highlighted
        )
    return highlighted

# =====================================================
# SCAM TYPE CLASSIFIER
# =====================================================

def classify_scam_type(detected_keywords, structural_reasons):
    types = []
    kw_text = " ".join(detected_keywords).lower()
    sr_text = " ".join(structural_reasons).lower()
    combined = kw_text + " " + sr_text

    if any(w in combined for w in ["package", "reship", "forward package"]):
        types.append("📦 Reshipping Scam")
    if any(w in combined for w in ["transfer funds", "wire transfer", "process payment", "money mule", "financial agent"]):
        types.append("💸 Money Mule Scam")
    if any(w in combined for w in ["impersonation", "university", "institutional", "dean", "professor"]):
        types.append("🎓 Institution Impersonation")
    if any(w in combined for w in ["bank account", "social security", "ssn", "full name", "personal data"]):
        types.append("🎣 Phishing / Data Harvesting")
    if any(w in combined for w in ["telegram", "whatsapp", "kindly text", "contact us on"]):
        types.append("📱 Social Media Recruitment Scam")
    if any(w in combined for w in ["passive income", "earn fast", "quick money", "crypto", "investment"]):
        types.append("💰 Investment / Get-Rich-Quick Scam")
    if any(w in combined for w in ["work from home", "earn from home", "remote", "work remotely"]):
        types.append("🏠 Fake Remote Job Scam")
    if not types:
        types.append("⚠️ General Job Scam")
    return types

# =====================================================
# RISK BREAKDOWN BARS
# =====================================================

def render_risk_breakdown(result, prob):
    ml_contrib = round(prob * 35, 1)
    kw_contrib = result["keyword_risk"]
    struct_contrib = result.get("structural_risk", 0)
    email_contrib = round(min(result.get("email_risk_raw", 0) * 0.15, 20), 1)
    url_contrib = round(min(result.get("url_risk_raw", 0), 30), 1)
    phone_contrib = round(min(result.get("phone_risk_raw", 0) * 0.1, 10), 1)

    bars = [
        ("ML Model", ml_contrib, 35, "#38BDF8"),
        ("Keywords", kw_contrib, 60, "#F59E0B"),
        ("Structural", struct_contrib, 40, "#A78BFA"),
        ("Email", email_contrib, 20, "#34D399"),
        ("URL", url_contrib, 30, "#F87171"),
        ("Phone", phone_contrib, 10, "#FB923C"),
    ]

    html = '<div class="risk-bar-wrap"><div class="section-header" style="margin-top:0">Risk Breakdown</div>'
    for label, val, max_val, color in bars:
        pct = min(int((val / max_val) * 100), 100) if max_val > 0 else 0
        html += f"""
        <div class="risk-bar-label"><span>{label}</span><span>{val}/{max_val} pts</span></div>
        <div class="risk-bar-outer">
            <div class="risk-bar-inner" style="width:{pct}%; background:{color};"></div>
        </div>"""
    html += "</div>"
    st.markdown(html, unsafe_allow_html=True)

# =====================================================
# GAUGE
# =====================================================

def render_gauge(score, label="Final Risk Score"):
    if score >= 60:
        color = "#EF4444"
        status = "HIGH RISK"
    elif score >= 35:
        color = "#F59E0B"
        status = "MEDIUM RISK"
    else:
        color = "#22C55E"
        status = "LOW RISK"

    pct = min(int(score), 100)
    circumference = 2 * 3.14159 * 54
    dash = circumference * pct / 100
    gap = circumference - dash

    svg = f"""
    <div class="gauge-wrap">
        <div class="gauge-label">{label}</div>
        <svg width="130" height="130" viewBox="0 0 130 130">
            <circle cx="65" cy="65" r="54" fill="none" stroke="var(--bg-tertiary)" stroke-width="12"/>
            <circle cx="65" cy="65" r="54" fill="none" stroke="{color}" stroke-width="12"
                stroke-dasharray="{dash:.1f} {gap:.1f}"
                stroke-dashoffset="{circumference * 0.25:.1f}"
                stroke-linecap="round"/>
            <text x="65" y="60" text-anchor="middle" font-size="26" font-weight="bold"
                fill="{color}" font-family="Space Mono, monospace">{score}</text>
            <text x="65" y="80" text-anchor="middle" font-size="10"
                fill="var(--text-secondary)" font-family="Inter, sans-serif">{status}</text>
        </svg>
    </div>
    """
    st.markdown(svg, unsafe_allow_html=True)

# =====================================================
# STAT BADGES (top right)
# =====================================================

def render_stat_badges():
    st.markdown(f"""
    <div class="stat-bar">
        <span class="stat-badge total">🔍 {st.session_state.total_scans} Scans</span>
        <span class="stat-badge scam">🚨 {st.session_state.scams_caught} Scams</span>
        <span class="stat-badge suspicious">⚠️ {st.session_state.suspicious_jobs} Suspicious</span>
        <span class="stat-badge legit">✅ {st.session_state.legit_jobs} Legitimate</span>
    </div>
    """, unsafe_allow_html=True)

# =====================================================
# HEADER
# =====================================================

col_title, col_stats = st.columns([2, 3])

with col_title:
    st.markdown("""
    <div class="shield-header">
        <div class="shield-title">🛡️ SCAMSHIELD</div>
        <div class="shield-subtitle">AI Powered Job Scam Detection</div>
    </div>
    """, unsafe_allow_html=True)

with col_stats:
    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    render_stat_badges()
    st.markdown(f'<div class="time-box">🕐 {get_ist_time()}</div>', unsafe_allow_html=True)

st.markdown("---")

# =====================================================
# SIDEBAR
# =====================================================

with st.sidebar:
    st.markdown("### 🛡️ SCAMSHIELD")
    st.markdown("---")

    # News on top
    st.markdown("#### 📰 Latest Scam News")
    if st.button("Load Latest News", use_container_width=True):
        news = api_checks.get_latest_scam_news()
        if news:
            for article in news:
                st.markdown("---")
                st.write(f"**{article['title']}**")
                st.caption(article["source"])
                st.write(article["url"])
        else:
            st.warning("Could not load news")

    st.markdown("---")

    # Features dropdown
    with st.expander("⚙️ Active Features"):
        st.success("✅ OCR — Optical Character Recognition")
        st.success("✅ ML — Random Forest Classifier")
        st.success("✅ Email Intelligence (Heuristic)")
        st.success("✅ Phone Number Analysis")
        st.success("✅ VirusTotal URL Scanner")
        st.success("✅ Google Safe Browsing")
        st.success("✅ Keyword Engine (60+ rules)")
        st.success("✅ Structural Pattern Detection")
        st.success("✅ Scam Type Classifier")
        st.success("✅ Text Highlighter")
        st.success("✅ Session Statistics")

    st.markdown("---")
    st.caption("SCAMSHIELD v2.0 | AI + OCR + Cybersecurity")

# =====================================================
# SEARCH BAR
# =====================================================

st.markdown('<div class="section-header">Search Previous Scam Logs</div>', unsafe_allow_html=True)

search_query = st.text_input(
    "Search Scam Logs",
    placeholder="Search previously analyzed job posts...",
    label_visibility="collapsed"
)

if search_query:
    try:
        df = pd.read_csv("live_training_data.csv")
        results = df[df["text"].str.contains(search_query, case=False, na=False)]
        if len(results) > 0:
            st.success(f"✅ {len(results)} matching records found")
            st.dataframe(results, use_container_width=True)
        else:
            st.warning("No matching records found in scan history")
    except FileNotFoundError:
        st.info("No scan history yet — analyze a job post first to build the log.")
    except Exception as e:
        st.error(f"Could not load scan history: {e}")

st.markdown("---")

# =====================================================
# INPUT SECTION
# =====================================================

st.markdown('<div class="section-header">Analyze Job Post</div>', unsafe_allow_html=True)

option = st.radio(
    "Choose Input Type",
    ["✏️ Text Input", "🖼️ Image Upload"],
    horizontal=True
)

text_input = ""

if option == "✏️ Text Input":
    text_input = st.text_area(
        "Paste Job Description or Email",
        height=220,
        placeholder="Paste the job post, recruitment email, or any suspicious message here..."
    )

else:
    uploaded_file = st.file_uploader(
        "Upload Screenshot",
        type=["png", "jpg", "jpeg", "avif"]
    )

    if uploaded_file:
        with open("temp.png", "wb") as f:
            f.write(uploaded_file.getbuffer())

        col1, col2 = st.columns([1, 2])

        with col1:
            st.image(uploaded_file, width=250)

        with st.spinner("🔍 Running OCR Detection..."):
            text_input = extract_text_from_image("temp.png")

        with col2:
            st.markdown("**OCR Extracted Text:**")
            st.code(text_input, language=None)

# =====================================================
# ANALYZE BUTTON
# =====================================================

analyze_clicked = st.button("🔍 Analyze Job Post", use_container_width=True, type="primary")

if analyze_clicked:

    if not text_input.strip():
        st.warning("⚠️ Please enter text or upload an image first.")
        st.stop()

    with st.spinner("🧠 Running Full Scam Analysis..."):
        result = analyze_job(text_input)

    # Update session stats
    st.session_state.total_scans += 1
    if result["result"] == "SCAM JOB DETECTED":
        st.session_state.scams_caught += 1
    elif result["result"] == "SUSPICIOUS JOB":
        st.session_state.suspicious_jobs += 1
    else:
        st.session_state.legit_jobs += 1

    st.markdown("---")

    # =================================================
    # VERDICT
    # =================================================

    if result["result"] == "SCAM JOB DETECTED":
        st.markdown('<div class="verdict-danger">🚨 SCAM JOB DETECTED</div>', unsafe_allow_html=True)
    elif result["result"] == "SUSPICIOUS JOB":
        st.markdown('<div class="verdict-warning">⚠️ SUSPICIOUS JOB</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="verdict-safe">✅ LEGITIMATE JOB</div>', unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # =================================================
    # SCAM TYPE
    # =================================================

    if result["result"] != "LEGITIMATE JOB":
        scam_types = classify_scam_type(
            result["detected_keywords"],
            result.get("structural_reasons", [])
        )
        st.markdown('<div class="section-header">Scam Type Identified</div>', unsafe_allow_html=True)
        tags_html = "".join([f'<span class="scam-type-tag">{t}</span>' for t in scam_types])
        st.markdown(tags_html, unsafe_allow_html=True)

    # =================================================
    # GAUGE + BREAKDOWN
    # =================================================

    st.markdown('<div class="section-header">Risk Analysis</div>', unsafe_allow_html=True)

    col_gauge, col_break = st.columns([1, 2])

    with col_gauge:
        render_gauge(result["risk_score"])
        st.markdown(f"""
        <div style="text-align:center; margin-top:12px;">
            <div style="font-size:13px; color:var(--text-secondary);">ML Scam Probability</div>
            <div style="font-size:28px; font-weight:700; color:var(--accent); font-family:'Space Mono',monospace;">{result['ml_score']}%</div>
        </div>
        """, unsafe_allow_html=True)

    with col_break:
        render_risk_breakdown(result, result["ml_score"] / 100)

    # =================================================
    # WHY IT WAS FLAGGED
    # =================================================

    st.markdown('<div class="section-header">Why This Was Flagged</div>', unsafe_allow_html=True)

    reasons = []

    if result["ml_score"] > 50:
        reasons.append(f"ML model flagged {result['ml_score']}% scam probability")
    if result["keyword_risk"] > 0:
        reasons.append(f"Scam-related keywords detected (keyword risk: {result['keyword_risk']} pts)")
    if len(result["phones"]) > 0:
        reasons.append("Phone numbers detected — suspicious recruiter contact")
    if len(result["urls"]) > 0:
        reasons.append("URLs found and scanned via VirusTotal + Google Safe Browsing")
    if result["email_results"]:
        for e in result["email_results"]:
            if e["final_email_risk"] > 40:
                reasons.append(f"Suspicious email detected: {e['email']}")
    for sr in result.get("structural_reasons", []):
        reasons.append(sr)
    if result["risk_score"] > 75:
        reasons.append("Overall risk score extremely high")
    if not reasons:
        reasons.append("No strong scam indicators found")

    for r in reasons:
        st.markdown(f'<div class="reason-item">⚡ {r}</div>', unsafe_allow_html=True)

    # =================================================
    # TEXT HIGHLIGHTER
    # =================================================

    if result["detected_keywords"]:
        st.markdown('<div class="section-header">🔦 Scam Phrases Highlighted</div>', unsafe_allow_html=True)
        highlighted = highlight_text(text_input, result["detected_keywords"])
        st.markdown(f'<div class="highlighted-text">{highlighted}</div>', unsafe_allow_html=True)

    # =================================================
    # EMAIL INTELLIGENCE
    # =================================================

    st.markdown('<div class="section-header">Email Intelligence</div>', unsafe_allow_html=True)

    if result["email_results"]:
        for e in result["email_results"]:
            risk_color = "#EF4444" if e["final_email_risk"] > 60 else "#F59E0B" if e["final_email_risk"] > 30 else "#22C55E"
            st.markdown(f"""
            <div class="info-box">
                <div class="label">Email Address</div>
                <div class="value">{e['email']}</div>
                <div style="margin-top:8px; font-size:13px; color:{risk_color}; font-weight:600;">
                    Risk Score: {e['final_email_risk']}/100
                </div>
                <div style="margin-top:4px; font-size:13px; color:var(--text-secondary);">
                    {" | ".join(e['reasons']) if e['reasons'] else "Free email provider detected"}
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.success("✅ No emails detected")

    # =================================================
    # PHONE DETECTION
    # =================================================

    st.markdown('<div class="section-header">Phone Number Detection</div>', unsafe_allow_html=True)

    if result["phones"]:
        for p in result["phone_results"]:
            risk_color = "#EF4444" if p["risk_score"] > 60 else "#F59E0B" if p["risk_score"] > 30 else "#22C55E"
            reasons_text = " | ".join(p["reasons"]) if p["reasons"] else "Suspicious recruiter contact"
            st.markdown(f"""
            <div class="info-box">
                <div class="label">Phone Number</div>
                <div class="value">{p['phone']}</div>
                <div style="margin-top:8px; font-size:13px; color:{risk_color}; font-weight:600;">
                    Risk Score: {p['risk_score']}/100
                </div>
                <div style="margin-top:4px; font-size:13px; color:var(--text-secondary);">{reasons_text}</div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.success("✅ No phone numbers detected")

    # =================================================
    # URL SECURITY
    # =================================================

    st.markdown('<div class="section-header">URL Security Analysis</div>', unsafe_allow_html=True)

    if result["url_results"]:
        for item in result["url_results"]:
            gs = item["google_safe_browsing"]
            vt = item["virustotal"]
            gs_color = "#EF4444" if gs == "unsafe" else "#22C55E"
            gs_label = "🚨 UNSAFE" if gs == "unsafe" else "✅ Safe"
            vt_mal = vt.get("malicious", 0) if isinstance(vt, dict) else 0
            vt_color = "#EF4444" if vt_mal > 0 else "#22C55E"
            st.markdown(f"""
            <div class="info-box">
                <div class="label">URL</div>
                <div class="value" style="word-break:break-all;">{item['url']}</div>
                <div style="display:flex; gap:16px; margin-top:10px; font-size:13px; font-weight:600;">
                    <span style="color:{gs_color}">Google Safe Browsing: {gs_label}</span>
                    <span style="color:{vt_color}">VirusTotal Malicious: {vt_mal}</span>
                </div>
                {"".join([f'<div style="font-size:12px;color:#F59E0B;margin-top:4px;">⚠️ {r}</div>' for r in item.get("reasons",[])])}
            </div>
            """, unsafe_allow_html=True)
    else:
        st.success("✅ No URLs detected")

    # Keywords section removed per user request — shown via highlighter instead

# =====================================================
# FEEDBACK
# =====================================================

st.markdown("---")
st.markdown('<div class="section-header">Submit Feedback</div>', unsafe_allow_html=True)

feedback_text = st.text_area(
    "Report incorrect detection or suggest improvements",
    placeholder="e.g. This job was incorrectly flagged as a scam...",
    key="feedback_input"
)

if st.button("📨 Submit Feedback", use_container_width=False):
    if feedback_text.strip():
        try:
            save_feedback(feedback_text.strip())
            st.success("✅ Feedback saved successfully — thank you!")
        except Exception as e:
            st.error(f"Could not save feedback: {e}")
    else:
        st.warning("Please write something before submitting.")

# =====================================================
# FOOTER
# =====================================================

st.markdown("---")
st.markdown("""
<div style="text-align:center; color:var(--text-secondary); font-size:12px; padding:10px 0;">
    SCAMSHIELD v2.0 &nbsp;|&nbsp; AI + OCR + Cybersecurity Scam Detection &nbsp;|&nbsp;
    Built with Streamlit
</div>
""", unsafe_allow_html=True)