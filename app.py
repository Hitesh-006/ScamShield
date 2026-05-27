
import streamlit as st
import pandas as pd
from datetime import datetime

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
# DARK PROFESSIONAL CSS
# =====================================================

st.markdown("""
<style>

.stApp {
    background-color: #0F172A;
    color: #F8FAFC;
}

.title {
    font-size: 46px;
    font-weight: bold;
    text-align: center;
    color: #38BDF8;
    margin-bottom: 5px;
}

.subtitle {
    text-align: center;
    color: #CBD5E1;
    margin-bottom: 25px;
    font-size: 18px;
}

.box {
    background: #1E293B;
    padding: 20px;
    border-radius: 14px;
    border: 1px solid #334155;
    margin-bottom: 18px;
}

.safe {
    background: #064E3B;
    color: #D1FAE5;
    padding: 18px;
    border-radius: 10px;
    font-size: 20px;
    font-weight: bold;
}

.warning {
    background: #78350F;
    color: #FEF3C7;
    padding: 18px;
    border-radius: 10px;
    font-size: 20px;
    font-weight: bold;
}

.danger {
    background: #7F1D1D;
    color: #FEE2E2;
    padding: 18px;
    border-radius: 10px;
    font-size: 20px;
    font-weight: bold;
}

.metric-box {
    background: #1E293B;
    padding: 18px;
    border-radius: 12px;
    border: 1px solid #334155;
    text-align: center;
}

.stTextArea textarea {
    background-color: #1E293B !important;
    color: white !important;
}

.stTextInput input {
    background-color: #1E293B !important;
    color: white !important;
}

</style>
""", unsafe_allow_html=True)

# =====================================================
# HEADER
# =====================================================

st.markdown(
    '<div class="title">SCAMSHIELD</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">AI Powered Job Scam Detection System</div>',
    unsafe_allow_html=True
)

# =====================================================
# TIME
# =====================================================

st.markdown(
    f"""
    <div class="box">
    Current Time: {datetime.now().strftime("%d %B %Y | %I:%M:%S %p")}
    </div>
    """,
    unsafe_allow_html=True
)

# =====================================================
# SEARCH BAR CONNECTED TO CSV
# =====================================================

st.markdown("## Search Previous Scam Logs")

search_query = st.text_input(
    "Search Scam Logs",
    placeholder="Search previously analyzed job posts..."
)

if search_query:
    try:
        df = pd.read_csv("live_training_data.csv")
        results = df[
            df["text"].str.contains(
                search_query,
                case=False,
                na=False
            )
        ]
        if len(results) > 0:
            st.success(f"{len(results)} matching records found")
            st.dataframe(results)
        else:
            st.warning("No matching records found in scan history")

    except FileNotFoundError:
        st.info("No scan history yet — analyze a job post first to build the log.")
    except Exception as e:
        st.error(f"Could not load scan history: {e}")

# =====================================================
# SIDEBAR
# =====================================================

st.sidebar.title("SCAMSHIELD")

st.sidebar.success("OCR Detection")
st.sidebar.success("Machine Learning")
st.sidebar.success("Email Intelligence API")
st.sidebar.success("Phone Detection")
st.sidebar.success("VirusTotal URL Scan")
st.sidebar.success("Google Safe Browsing")
st.sidebar.success("CSV + SQLite Storage")
# =====================================================
# LIVE SCAM NEWS SIDEBAR
# =====================================================

st.sidebar.markdown("## Latest Scam News")

if st.sidebar.button("Load News"):

    news = api_checks.get_latest_scam_news()

    if news:

        for article in news:

            st.sidebar.markdown("---")

            st.sidebar.write(article["title"])

            st.sidebar.caption(article["source"])

            st.sidebar.write(article["url"])

    else:

        st.sidebar.warning("Could not load news")

# =====================================================
# INPUT SECTION
# =====================================================

st.markdown('<div class="box">', unsafe_allow_html=True)

option = st.radio(
    "Choose Input Type",
    ["Text Input", "Image Upload"]
)

text_input = ""

# =====================================================
# TEXT INPUT
# =====================================================

if option == "Text Input":

    text_input = st.text_area(
        "Paste Job Description",
        height=250
    )

# =====================================================
# IMAGE INPUT
# =====================================================

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

        with st.spinner("Running OCR Detection..."):

            text_input = extract_text_from_image("temp.png")

        with col2:

            st.markdown("### OCR Extracted Text")

            st.code(text_input)

st.markdown("</div>", unsafe_allow_html=True)

# =====================================================
# ANALYZE BUTTON
# =====================================================

if st.button("Analyze Job Post", use_container_width=True):

    if not text_input.strip():

        st.warning("Please enter text or upload image")

        st.stop()

    with st.spinner("Running Full Scam Analysis..."):

        result = analyze_job(text_input)

    # =================================================
    # FINAL RESULT
    # =================================================

    if result["result"] == "SCAM JOB DETECTED":

        st.markdown(
            f'<div class="danger">{result["result"]}</div>',
            unsafe_allow_html=True
        )

    elif result["result"] == "SUSPICIOUS JOB":

        st.markdown(
            f'<div class="warning">{result["result"]}</div>',
            unsafe_allow_html=True
        )

    else:

        st.markdown(
            f'<div class="safe">{result["result"]}</div>',
            unsafe_allow_html=True
        )

    st.write("")

    # =================================================
    # SCORES
    # =================================================

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "ML Scam Probability",
            f"{result['ml_score']}%"
        )

    with col2:

        st.metric(
            "Final Risk Score",
            result["risk_score"]
        )

    with col3:

        st.metric(
            "Emails Found",
            len(result["emails"])
        )

    # =================================================
    # WHY IT IS A SCAM
    # =================================================
# =================================================
# WHY IT IS A SCAM
# =================================================

    st.markdown("## Why This Was Flagged")

    reasons = []

    if result["ml_score"] > 50:
        reasons.append(
            f"ML model flagged {result['ml_score']}% scam probability"
        )

    if result["keyword_risk"] > 0:
        reasons.append(
            f"Scam-related keywords detected (keyword risk: {result['keyword_risk']})"
        )

    if len(result["phones"]) > 0:
        reasons.append(
            "Phone numbers detected (suspicious recruiter contact)"
        )

    if len(result["urls"]) > 0:
        reasons.append(
            "URLs detected and scanned"
        )

    if result["email_results"]:
        for e in result["email_results"]:
            if e["final_email_risk"] > 40:
                reasons.append(
                    f"Suspicious email detected: {e['email']}"
                )

    for sr in result.get("structural_reasons", []):
        reasons.append(sr)

    if result["risk_score"] > 75:
        reasons.append(
            "Overall risk score extremely high"
        )

    if not reasons:
        reasons.append(
            "No strong scam indicators found"
        )

    for r in reasons:
        st.write("•", r)

    # =================================================
    # EMAIL ANALYSIS
    # =================================================

    st.markdown("## Email Intelligence")

    if result["email_results"]:
        for e in result["email_results"]:
            st.markdown('<div class="box">', unsafe_allow_html=True)
            st.write("Email:", e["email"])
            st.write("Risk Score:", e["final_email_risk"])
            if e["reasons"]:
                st.write("Reasons:", ", ".join(e["reasons"]))
            else:
                st.write("Reasons: Free email provider detected")
            st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.success("No emails detected")

    # =================================================
    # PHONE ANALYSIS
    # =================================================

    st.markdown("## Phone Number Detection")

    if result["phones"]:

        for p in result["phones"]:

            st.markdown('<div class="box">', unsafe_allow_html=True)

            st.write("Phone Number:", p)

            st.write(
                "Status: Suspicious recruiter contact"
            )

            st.markdown("</div>", unsafe_allow_html=True)

    else:

        st.success("No phone numbers detected")

    # =================================================
    # URL ANALYSIS
    # =================================================

    st.markdown("## URL Security Analysis")

    if result["url_results"]:

        for item in result["url_results"]:

            st.markdown('<div class="box">', unsafe_allow_html=True)

            st.write("URL:", item["url"])

            st.write(
                "VirusTotal:",
                item["virustotal"]
            )

            st.write(
                "Google Safe Browsing:",
                item["google_safe_browsing"]
            )

            st.write(
                "Heuristic Result:",
                item["reasons"]
            )

            st.markdown("</div>", unsafe_allow_html=True)

    else:

        st.success("No URLs detected")

    # =================================================
    # KEYWORDS
    # =================================================

    st.markdown("## Suspicious Keywords")

    if result["detected_keywords"]:

        for word in result["detected_keywords"]:

            st.warning(word)

    else:

        st.success("No suspicious keywords detected")

    
# =====================================================
# FEEDBACK
# =====================================================

st.markdown("---")

st.subheader("Feedback")

feedback = st.text_area(
    "Report incorrect detection"
)

if st.button("Submit Feedback"):

    if feedback.strip():

        save_feedback(feedback)

        st.success("Feedback stored successfully")

# =====================================================
# FOOTER
# =====================================================

st.markdown("---")

st.caption(
    "SCAMSHIELD | AI + OCR + Cybersecurity Scam Detection")
