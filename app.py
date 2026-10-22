"""
Scam Shield (स्कैम शील्ड) - An accessible scam detection tool for India.
Built with Streamlit, google-genai, and python-dotenv.
"""

import os
import re
import json
import html
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from dotenv import load_dotenv
import streamlit as st

# Load environment variables from .env file (with override=True to detect user updates)
load_dotenv(override=True)

# Configuration constants for Gemini 3.5 Flash Lite
MODEL_NAME = "gemini-3.5-flash-lite"
REQUEST_TIMEOUT_MS = 20000  # 20 seconds finite timeout
MAX_RETRIES = 0             # SDK retries are bounded; no multiple long retry loops

# ==============================================================================
# 1. DATA MODELS & SCHEMAS
# ==============================================================================

class ScamAnalysisResult(BaseModel):
    """Structured response schema for Gemini AI scam analysis."""
    verdict: str = Field(
        description="Must be exactly 'SCAM', 'SUSPICIOUS', or 'SAFE'."
    )
    scam_type: str = Field(
        description="Category/type of message, e.g. 'Electricity Bill Scam', 'Bank KYC / Phishing APK', 'WhatsApp Lottery Scam', 'Digital Arrest Threat', 'Legitimate Transactional Alert'."
    )
    explanation: str = Field(
        description="A single clear, reassuring, plain-language sentence explaining the verdict, suitable for a parent or grandparent."
    )
    red_flags: List[str] = Field(
        description="2 to 3 concise bullet points highlighting specific warning signs or why the message is considered safe."
    )
    recommended_actions: List[str] = Field(
        description="2 to 3 practical, concrete next steps the user should take immediately (e.g. block sender, do not click link, call 1930)."
    )
    confidence: str = Field(
        description="Confidence level: 'HIGH', 'MEDIUM', or 'LOW'."
    )


# ==============================================================================
# 2. SAMPLE MESSAGES FOR EASY BEGINNER TESTING
# ==============================================================================

SAMPLE_MESSAGES = {
    "⚡ Electricity Disconnection": (
        "Dear Consumer, Your Electricity power will be disconnected tonight at 9:30 PM from "
        "the electricity office because your previous month bill was not updated. Please immediately "
        "contact our electricity officer Rahul Sharma at 9876543210 or update bill through link: "
        "http://bit.ly/bijli-bill-pay"
    ),
    "🏦 SBI / YONO KYC Expiry APK": (
        "Dear Customer, Your SBI YONO account has been suspended due to pending KYC verification. "
        "Please click the link below to download our KYC update app and prevent account freeze: "
        "http://sbi-yono-update.xyz/app.apk. Do not ignore."
    ),
    "🎁 WhatsApp ₹25 Lakh KBC Lottery": (
        "Badhai ho! Aapka number KBC WhatsApp lucky draw me chuna gaya hai aur aapne jeete hain "
        "₹25,00,000 cash prize. Apne inaam ki rashi pane ke liye turant WhatsApp karein Rana Pratap Singh "
        "ko 9123456789 par aur registration fee ₹2,500 jama karein."
    ),
    "👮 Digital Arrest / Courier Threat": (
        "URGENT NOTICE: This is Inspector Ajay Kumar from Mumbai Cyber Crime Branch. A FedEx parcel sent "
        "to Taiwan under your Aadhaar details contains 5 fake passports and 140 grams of narcotics. "
        "An FIR has been registered. You must connect on Skype immediately for interrogation under "
        "Digital Arrest warrant to avoid arrest."
    ),
    "✅ Legitimate Bank Transaction": (
        "Dear Customer, your A/C XX4921 has been debited by Rs 1,250.00 on 22-Oct-26 at Apollo Pharmacy "
        "via UPI. Avail Bal: Rs 24,180.50. If not done by you, call 1800-11-2211 or SMS NO to 567676 - State Bank of India"
    )
}


# ==============================================================================
# 3. RULE-BASED DETECTION ENGINE (TRANSPARENT HEURISTICS)
# ==============================================================================

def analyze_rules(text: str) -> Dict[str, Any]:
    """
    Performs transparent, explainable heuristic checks tailored to common scams in India.
    Supports English, Hindi, and Hinglish phrases.
    """
    lower = text.lower()
    findings = []
    
    # Check 1: Urgent Threats & Panic Inducers (English + Hinglish/Hindi)
    threat_patterns = [
        (r"\b(disconnected tonight|power cutoff|electricity cut|bijli kat|bijli cut|aaj raat bijli)\b", "Electricity disconnection threat tonight", "HIGH"),
        (r"\b(account suspended|account blocked|khata band|card blocked|sim block|sim band)\b", "Threat of account or SIM deactivation", "HIGH"),
        (r"\b(immediately|within 24 hours|within 2 hrs|within 1 hour|turant|aakhri mauka|final notice|last notice)\b", "Artificial urgency / short deadline pressure", "MEDIUM"),
        (r"\b(digital arrest|arrest warrant|fir registered|cbi custody|ed interrogation|narcotics parcel|giraftari|police karyawahi)\b", "Severe threat of police arrest, drugs parcel, or Digital Arrest", "CRITICAL"),
    ]
    urgency_hits = []
    max_urgency_sev = "LOW"
    for pattern, description, sev in threat_patterns:
        if re.search(pattern, lower):
            urgency_hits.append(description)
            if sev == "CRITICAL" or (sev == "HIGH" and max_urgency_sev != "CRITICAL"):
                max_urgency_sev = sev
            elif sev == "MEDIUM" and max_urgency_sev == "LOW":
                max_urgency_sev = "MEDIUM"
    if urgency_hits:
        findings.append({
            "category": "Urgent Threats & Fear Tactics",
            "icon": "⏱️",
            "details": urgency_hits,
            "severity": max_urgency_sev
        })

    # Check 2: Sensitive Credential & Data Harvesting
    credential_patterns = [
        (r"\b(otp|one time password|apna otp|otp bheje|otp batayein|share otp|send otp)\b", "Requesting One-Time Password (OTP)", "CRITICAL"),
        (r"\b(mpin|upi pin|pin number|atm pin|cvv|password)\b", "Requesting security PIN, CVV, or password", "CRITICAL"),
        (r"\b(pan card details|aadhaar link|update kyc|kyc expired|yono kyc|kyc update|pending kyc|kyc verification|re-kyc)\b", "Urgent KYC or Aadhaar/PAN verification demand", "HIGH"),
    ]
    cred_hits = []
    max_cred_sev = "LOW"
    for pattern, description, sev in credential_patterns:
        if re.search(pattern, lower):
            cred_hits.append(description)
            if sev == "CRITICAL" or (sev == "HIGH" and max_cred_sev != "CRITICAL"):
                max_cred_sev = sev
    if cred_hits:
        findings.append({
            "category": "Credential & KYC Demands",
            "icon": "🔑",
            "details": cred_hits,
            "severity": max_cred_sev
        })

    # Check 3: Shortened URLs, Lookalike Domains, & APK Downloads
    link_patterns = [
        (r"\b[\w\-.]+\.apk\b", "Direct Android Application Package (.apk) download link (High malware risk)", "CRITICAL"),
        (r"\b(bit\.ly|tinyurl\.com|is\.gd|t\.co|cutt\.ly|rb\.gy|shorturl\.at|goo\.gl|ow\.ly)\b", "Shortened / obfuscated URL detected", "HIGH"),
        (r"\b(?:https?:\/\/)?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:\/\S*)?\b", "Suspicious raw IP address link instead of domain", "HIGH"),
        (r"\.(xyz|top|online|click|site|work|vip|live|loan|cam|rest|space)\b", "Uncommon or high-risk domain extension (.xyz, .top, etc.)", "HIGH"),
        (r"\b(?:sbi|yono|hdfc|icici|electricity|bijli|trai|epfo)[\w\-]*\.(?:com|org|net|xyz|site|info)\b", "Potential lookalike / fake brand domain", "HIGH")
    ]
    link_hits = []
    max_link_sev = "LOW"
    for pattern, description, sev in link_patterns:
        if re.search(pattern, lower):
            link_hits.append(description)
            if sev == "CRITICAL" or (sev == "HIGH" and max_link_sev != "CRITICAL"):
                max_link_sev = sev
    if link_hits:
        findings.append({
            "category": "Suspicious Links & Downloads",
            "icon": "🔗",
            "details": link_hits,
            "severity": max_link_sev
        })

    # Check 4: Payment Demands, Lottery Claims & Advance Fees
    payment_patterns = [
        (r"\b(kbc|lottery|lucky draw|inaam|jeete hain|won \d+|cash prize|25 lakh)\b", "Unsolicited lottery or prize winnings announcement", "HIGH"),
        (r"\b(registration fee|processing fee|advance charge|tax deposit|shulk)\b", "Demanding advance payment or registration fee", "HIGH"),
        (r"\b(scan qr code to receive|enter upi pin to receive|receive money via qr)\b", "Fraudulent claim that entering UPI PIN receives money", "CRITICAL"),
    ]
    pay_hits = []
    max_pay_sev = "LOW"
    for pattern, description, sev in payment_patterns:
        if re.search(pattern, lower):
            pay_hits.append(description)
            if sev == "CRITICAL" or (sev == "HIGH" and max_pay_sev != "CRITICAL"):
                max_pay_sev = sev
    if pay_hits:
        findings.append({
            "category": "Payment Demands & Lottery Traps",
            "icon": "💸",
            "details": pay_hits,
            "severity": max_pay_sev
        })

    # Check 5: Impersonation of Government / Banks / Utilities
    impersonation_patterns = [
        (r"\b(sbi|yono|hdfc|icici|pnb|axis bank|state bank)\b", "Bank name mentioned"),
        (r"\b(electricity office|bijli vibhag|power board|mahavitaran|bescom|bses|uppcl|tneb|discom)\b", "Power / Electricity Board mention"),
        (r"\b(trai|telecom authority|department of telecommunications|dot|india post|customs department)\b", "Government department or regulatory agency mention"),
        (r"\b(mumbai police|delhi police|cbi|cyber cell|enforcement directorate)\b", "Law enforcement or investigative agency mention"),
    ]
    imp_hits = []
    for pattern, description in impersonation_patterns:
        if re.search(pattern, lower):
            imp_hits.append(description)
    if imp_hits:
        findings.append({
            "category": "Official Organization Mentions",
            "icon": "🏛️",
            "details": imp_hits,
            "severity": "MEDIUM"
        })

    # Calculate heuristic score
    score = 0
    for f in findings:
        if f["severity"] == "CRITICAL":
            score += 4
        elif f["severity"] == "HIGH":
            score += 2
        elif f["severity"] == "MEDIUM":
            score += 1

    return {
        "score": score,
        "findings": findings,
        "has_high_risk": any(f["severity"] in ["CRITICAL", "HIGH"] for f in findings)
    }


# ==============================================================================
# 4. GEMINI AI ANALYSIS VIA GOOGLE GEN AI SDK
# ==============================================================================

def analyze_with_gemini(text: str, rule_signals: Dict[str, Any], api_key: str) -> Dict[str, Any]:
    """
    Analyzes message with Gemini 3.5 Flash Lite using the official google-genai SDK.
    Configured with 20s request timeout, bounded SDK retries, and structured Pydantic schema.
    """
    try:
        from google import genai
        from google.genai import types
        from google.genai.errors import APIError
        import httpx
    except ImportError:
        return {
            "error_type": "SDK_IMPORT_ERROR",
            "error_title": "Library Import Error",
            "error_message": "The google-genai library is not properly installed. Please verify your environment."
        }

    # Format the rule findings for the prompt
    rule_summary = []
    for item in rule_signals.get("findings", []):
        rule_summary.append(f"- {item['category']} ({item['severity']}): {', '.join(item['details'])}")
    rule_context = "\n".join(rule_summary) if rule_summary else "No automatic heuristic patterns were triggered."

    system_instruction = (
        "You are 'Scam Shield', an expert digital fraud investigator and empathetic cyber safety assistant for families in India.\n"
        "Your mission is to protect elderly parents, grandparents, and first-time smartphone users from cyber financial fraud.\n\n"
        "GUIDELINES & CONSTRAINTS:\n"
        "1. Understand Indian scam modalities thoroughly: Electricity bill disconnection threats, Fake SBI/HDFC/ICICI KYC expiry, "
        "malicious Android APK downloads, WhatsApp KBC lottery fees, Digital Arrest / Police Skype interrogation threats, "
        "and UPI QR code payment inversion tricks.\n"
        "2. Seamlessly understand English, Hindi (Devanagari), and Hinglish (Hindi written in Roman script, e.g., 'bijli kat jayegi', 'turant sampark karein').\n"
        "3. NEVER treat keyword matches alone as proof of a scam. Legitimate bank transaction SMS (e.g. 'Rs 500 debited for groceries') contains bank names and amounts but is safe.\n"
        "4. If evidence is incomplete, ambiguous, or suspicious, ALWAYS choose 'SUSPICIOUS' rather than 'SAFE'. Erring on the side of caution protects the elderly.\n"
        "5. A 'SAFE' verdict explicitly means NO major warning signs were identified in the supplied text, NOT that the message is guaranteed authentic.\n"
        "6. NEVER claim or imply that this message has been verified or endorsed by any bank, police department, or government agency.\n"
        "7. Keep the explanation to ONE single, clear, reassuring sentence that an elderly parent or grandparent can easily grasp.\n"
        "8. Output MUST strictly adhere to the provided JSON schema."
    )

    user_prompt = f"""Analyze this message received by a user in India:

--- MESSAGE CONTENT ---
{text}
--- END MESSAGE ---

Pre-computed Heuristic Safety Signals:
{rule_context}

Please provide your evaluation with a verdict of SCAM, SUSPICIOUS, or SAFE."""

    # Set finite request timeout and bound SDK automatic retries
    http_opts = types.HttpOptions(
        timeout=REQUEST_TIMEOUT_MS,
        retry_options=types.HttpRetryOptions(attempts=1),
    )
    client = genai.Client(api_key=api_key, http_options=http_opts)

    # Configure Gemini 3.5 Flash Lite with structured Pydantic schema
    config = types.GenerateContentConfig(
        system_instruction=system_instruction,
        response_mime_type="application/json",
        response_schema=ScamAnalysisResult,
    )

    last_error_dict = None

    for attempt in range(MAX_RETRIES + 1):
        try:
            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=user_prompt,
                config=config,
            )

            if not response.text:
                return {
                    "error_type": "EMPTY_RESPONSE",
                    "error_title": "Empty AI Response",
                    "error_message": "Gemini returned an empty response. Please try again."
                }

            try:
                data = json.loads(response.text)
            except json.JSONDecodeError:
                return {
                    "error_type": "JSON_PARSE_ERROR",
                    "error_title": "Malformed AI Output",
                    "error_message": "Gemini returned output that could not be parsed as structured JSON."
                }

            # Validate fields
            verdict = str(data.get("verdict", "SUSPICIOUS")).upper().strip()
            if verdict not in ["SCAM", "SUSPICIOUS", "SAFE"]:
                verdict = "SUSPICIOUS"

            return {
                "success": True,
                "is_ai": True,
                "model_used": MODEL_NAME,
                "verdict": verdict,
                "scam_type": data.get("scam_type", "Suspicious Communication"),
                "explanation": data.get("explanation", "Please exercise caution with this message."),
                "red_flags": data.get("red_flags", ["Unusual communication pattern"]),
                "recommended_actions": data.get("recommended_actions", ["Do not click any links", "Do not share OTP"]),
                "confidence": data.get("confidence", "MEDIUM")
            }

        except APIError as api_err:
            err_msg = str(api_err)
            err_code = getattr(api_err, "code", None)

            # 1. Invalid API Key (400, 401, 403)
            if err_code in [400, 401, 403] or any(k in err_msg.lower() for k in ["api_key_invalid", "api key not valid", "permission_denied"]):
                return {
                    "error_type": "AUTH_ERROR",
                    "error_title": "Authentication Error",
                    "error_message": "AI service could not authenticate."
                }

            # 2. Unsupported Model (404)
            if err_code == 404 or any(k in err_msg.lower() for k in ["not found", "is not supported", "unsupported model"]):
                return {
                    "error_type": "UNSUPPORTED_MODEL",
                    "error_title": "Model Unavailable",
                    "error_message": "The AI model is currently unavailable."
                }

            # 3. Quota / Rate limit (429)
            if err_code == 429 or any(k in err_msg.lower() for k in ["resource_exhausted", "quota", "rate limit"]):
                return {
                    "error_type": "RATE_LIMIT",
                    "error_title": "Service Busy",
                    "error_message": "AI service is currently experiencing high demand. Please try again shortly."
                }

            # 4. Timeout (408, 504)
            if err_code in [408, 504] or any(k in err_msg.lower() for k in ["deadline_exceeded", "deadline expired", "timed out"]):
                last_error_dict = {
                    "error_type": "TIMEOUT",
                    "error_title": "Request Timed Out",
                    "error_message": "AI service did not respond within the expected time."
                }
                if attempt < MAX_RETRIES:
                    continue
                return last_error_dict

            # 5. Temporary High Demand / Service Unavailable (503)
            if err_code == 503 or "503" in err_msg or any(k in err_msg.lower() for k in ["high demand", "unavailable"]):
                last_error_dict = {
                    "error_type": "SERVICE_UNAVAILABLE",
                    "error_title": "Service Unavailable",
                    "error_message": "AI service is temporarily unavailable. Please try again shortly."
                }
                if attempt < MAX_RETRIES:
                    continue
                return last_error_dict

            # Other API Errors (never leak raw error messages or traces to users)
            last_error_dict = {
                "error_type": "API_ERROR",
                "error_title": "AI Service Error",
                "error_message": "AI service returned an unexpected response."
            }
            if attempt < MAX_RETRIES and err_code in [500, 502]:
                continue
            return last_error_dict

        except (httpx.TimeoutException, TimeoutError):
            last_error_dict = {
                "error_type": "TIMEOUT",
                "error_title": "Connection Timed Out",
                "error_message": "Network request to AI service timed out."
            }
            if attempt < MAX_RETRIES:
                continue
            return last_error_dict

        except (httpx.ConnectError, httpx.NetworkError):
            last_error_dict = {
                "error_type": "NETWORK_ERROR",
                "error_title": "Network Connection Error",
                "error_message": "Could not connect to AI service. Please check your internet connection."
            }
            if attempt < MAX_RETRIES:
                continue
            return last_error_dict

        except Exception:
            last_error_dict = {
                "error_type": "UNEXPECTED_ERROR",
                "error_title": "Unexpected Error",
                "error_message": "An unexpected error occurred during AI analysis."
            }
            break

    return last_error_dict or {
        "error_type": "UNKNOWN_ERROR",
        "error_title": "Analysis Incomplete",
        "error_message": "Could not complete AI analysis."
    }


# ==============================================================================
# 5. FALLBACK HEURISTIC-ONLY EVALUATION (WHEN API KEY IS NOT CONFIGURED)
# ==============================================================================

def analyze_heuristic_fallback(text: str, rule_signals: Dict[str, Any]) -> Dict[str, Any]:
    """
    Provides an emergency fallback risk appraisal based on rule heuristics when
    no Gemini API key is configured. Ensures the app remains 100% testable.
    """
    score = rule_signals.get("score", 0)
    findings = rule_signals.get("findings", [])
    
    flag_descriptions = []
    for f in findings:
        for detail in f.get("details", []):
            flag_descriptions.append(f"{f['icon']} {detail}")

    # Heuristic classification
    has_critical = any(f.get("severity") == "CRITICAL" for f in findings)

    if has_critical or score >= 3:
        verdict = "SCAM"
        scam_type = "High-Risk Fraud Pattern (Heuristic Detection)"
        explanation = "This message contains multiple severe warning signs typical of known scams in India, such as urgent threats, payment demands, or credential requests."
        actions = [
            "Do NOT click any link, scan QR codes, or download any APK file.",
            "Never share your OTP, PIN, or password with anyone.",
            "Block the sender number immediately and report to 1930 if money was lost."
        ]
        confidence = "HIGH"
    elif score >= 1:
        verdict = "SUSPICIOUS"
        scam_type = "Potential Risk (Heuristic Detection)"
        explanation = "This message contains suspicious urgency or link patterns that require caution before taking any action."
        actions = [
            "Verify independently using the official helpline or website of the company/bank.",
            "Do NOT use any phone numbers or links provided inside this message.",
            "Consult a tech-savvy family member or call the 1930 Cyber Helpline."
        ]
        confidence = "MEDIUM"
    else:
        # Rule: If evidence is incomplete or uncertain, use SUSPICIOUS rather than SAFE!
        verdict = "SUSPICIOUS"
        scam_type = "Unverified Text (Heuristic Preview)"
        explanation = "No obvious scam keywords were matched by the built-in rule checks, but further verification is recommended to ensure safety."
        flag_descriptions = [
            "No standard trigger keywords matched by built-in heuristics",
            "Contextual intent could not be evaluated by AI checks"
        ]
        actions = [
            "Always verify independently through official apps rather than SMS links.",
            "Never share OTPs, PINs, or passwords with unverified contacts.",
            "If in doubt, consult a tech-savvy family member or call the 1930 Cyber Helpline."
        ]
        confidence = "LOW"

    return {
        "success": True,
        "is_fallback": True,
        "verdict": verdict,
        "scam_type": scam_type,
        "explanation": explanation,
        "red_flags": flag_descriptions[:3] if flag_descriptions else ["No obvious keyword triggers detected"],
        "recommended_actions": actions,
        "confidence": confidence
    }


# ==============================================================================
# 6. API KEY RESOLUTION (STREAMLIT SECRETS -> ENVIRONMENT / .ENV)
# ==============================================================================

def get_gemini_api_key() -> Optional[str]:
    """
    Safely retrieves the Gemini API key without logging or exposing it.
    Order of precedence:
    1. Streamlit server-side secrets: st.secrets["GEMINI_API_KEY"] (for cloud deployment)
    2. Environment variable: os.getenv("GEMINI_API_KEY") (including values from .env for local dev)
    """
    # 1. Streamlit server-side secrets (for cloud deployment)
    try:
        if "GEMINI_API_KEY" in st.secrets:
            sec_key = st.secrets["GEMINI_API_KEY"]
            if sec_key and str(sec_key).strip() and str(sec_key).strip() != "your_gemini_api_key_here":
                return str(sec_key).strip()
    except Exception:
        # Gracefully handle missing secrets.toml or Streamlit secrets errors without crashing
        pass

    # 2. Environment variable / local .env file (for local development)
    try:
        env_key = os.getenv("GEMINI_API_KEY")
        if not env_key or env_key.strip() == "your_gemini_api_key_here":
            load_dotenv()
            env_key = os.getenv("GEMINI_API_KEY")
        if env_key and env_key.strip() and env_key.strip() != "your_gemini_api_key_here":
            return env_key.strip()
    except Exception:
        pass

    return None


# ==============================================================================
# 7. MAIN UI APPLICATION
# ==============================================================================

def render_app():
    # Page Configuration
    st.set_page_config(
        page_title="Scam Shield | Protect Your Family From Scams",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed"
    )

    # Custom Styling: Deep Navy/Emerald Indian Cyber Safety Theme
    custom_css = """
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Noto+Sans+Devanagari:wght@400;600;700&display=swap');

        html, body, [class*="css"] {
            font-family: 'Plus Jakarta Sans', 'Noto Sans Devanagari', -apple-system, BlinkMacSystemFont, sans-serif;
        }

        .stApp {
            background: radial-gradient(circle at 50% 0%, #0d1e38 0%, #081226 70%, #050b18 100%);
            color: #f1f5f9;
        }

        .hero-container {
            text-align: center;
            padding: 1.5rem 1rem 1rem 1rem;
            margin-bottom: 1rem;
        }
        .hero-title {
            font-size: 2.4rem;
            font-weight: 800;
            background: linear-gradient(135deg, #38bdf8 0%, #34d399 50%, #10b981 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.25rem;
            letter-spacing: -0.02em;
        }
        .hero-subtitle {
            font-size: 1.15rem;
            color: #94a3b8;
            max-width: 700px;
            margin: 0 auto;
            line-height: 1.5;
        }

        .helpline-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid rgba(239, 68, 68, 0.4);
            color: #fca5a5;
            padding: 6px 16px;
            border-radius: 9999px;
            font-size: 0.95rem;
            font-weight: 700;
            margin-top: 0.75rem;
        }

        .verdict-card {
            border-radius: 18px;
            padding: 28px;
            margin: 1.5rem 0;
            box-shadow: 0 16px 40px rgba(0, 0, 0, 0.45);
            border: 2px solid;
        }
        .verdict-scam {
            background: linear-gradient(145deg, rgba(127, 29, 29, 0.85) 0%, rgba(69, 10, 10, 0.95) 100%);
            border-color: #ef4444;
            color: #ffffff;
        }
        .verdict-suspicious {
            background: linear-gradient(145deg, rgba(146, 64, 14, 0.85) 0%, rgba(67, 20, 7, 0.95) 100%);
            border-color: #f59e0b;
            color: #ffffff;
        }
        .verdict-safe {
            background: linear-gradient(145deg, rgba(6, 78, 59, 0.85) 0%, rgba(2, 44, 34, 0.95) 100%);
            border-color: #10b981;
            color: #ffffff;
        }

        .verdict-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.15);
            padding-bottom: 0.75rem;
        }
        .verdict-title {
            font-size: 2.2rem;
            font-weight: 800;
            display: flex;
            align-items: center;
            gap: 12px;
            margin: 0;
        }
        .verdict-type {
            font-size: 1.25rem;
            font-weight: 600;
            color: #e2e8f0;
            margin-bottom: 1rem;
        }
        .verdict-explanation {
            font-size: 1.25rem;
            line-height: 1.6;
            font-weight: 500;
            padding: 14px 18px;
            background: rgba(0, 0, 0, 0.25);
            border-radius: 12px;
            margin-bottom: 1.25rem;
        }

        .result-section-title {
            font-size: 1.1rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 1.25rem;
            margin-bottom: 0.75rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .action-step-item {
            background: rgba(255, 255, 255, 0.08);
            border-left: 4px solid #38bdf8;
            padding: 12px 16px;
            border-radius: 0 10px 10px 0;
            margin-bottom: 8px;
            font-size: 1.05rem;
            font-weight: 500;
            line-height: 1.5;
            word-break: break-word;
        }
        .red-flag-item {
            background: rgba(239, 68, 68, 0.12);
            border-left: 4px solid #ef4444;
            padding: 12px 16px;
            border-radius: 0 10px 10px 0;
            margin-bottom: 8px;
            font-size: 1.05rem;
            font-weight: 500;
            line-height: 1.5;
            word-break: break-word;
        }

        .disclaimer-box {
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid rgba(148, 163, 184, 0.25);
            border-radius: 12px;
            padding: 14px 18px;
            font-size: 0.95rem;
            color: #94a3b8;
            line-height: 1.5;
            margin-top: 1.5rem;
        }

        .stTextArea textarea {
            font-size: 1.15rem !important;
            line-height: 1.6 !important;
            background-color: #0b1a30 !important;
            color: #f8fafc !important;
            border: 2px solid #243b5a !important;
            border-radius: 14px !important;
            padding: 16px !important;
        }
        .stTextArea textarea:focus {
            border-color: #38bdf8 !important;
            box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.25) !important;
        }

        .stButton button {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%) !important;
            color: #ffffff !important;
            font-size: 1.25rem !important;
            font-weight: 700 !important;
            padding: 14px 32px !important;
            border-radius: 12px !important;
            border: none !important;
            width: 100% !important;
            box-shadow: 0 4px 14px rgba(16, 185, 129, 0.4) !important;
            transition: all 0.2s ease-in-out !important;
        }
        .stButton button:hover {
            background: linear-gradient(135deg, #34d399 0%, #10b981 100%) !important;
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(16, 185, 129, 0.5) !important;
        }

        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
    </style>
    """
    st.markdown(custom_css, unsafe_allow_html=True)

    # Session state initialization for message input
    if "message_input" not in st.session_state:
        st.session_state["message_input"] = ""

    # Sidebar: About Scam Shield, Helplines & Privacy Notice
    with st.sidebar:
        st.header("🛡️ About Scam Shield")
        st.markdown(
            "Scam Shield is a free cyber safety assistant designed to help families in India "
            "identify potential digital fraud, malicious links, and scam messages."
        )

        st.markdown("---")
        st.markdown("### 🇮🇳 Emergency Indian Helplines")
        st.markdown("- **National Cybercrime**: Dial **1930**")
        st.markdown("- **Cybercrime Portal**: [cybercrime.gov.in](https://cybercrime.gov.in)")
        st.markdown("- **Chakshu Fraud Reporting**: [sancharsaathi.gov.in](https://sancharsaathi.gov.in)")
        st.markdown("- **Banking Ombudsman**: Dial **14448**")
        
        st.markdown("---")
        st.markdown("### 🔒 Privacy Notice")
        st.caption(
            "Scam Shield processes submitted text in real time to assess fraud risk. "
            "When AI analysis is active, text is evaluated using Google Gemini. "
            "For your security, never paste passwords, MPINs, OTPs, or sensitive banking details."
        )

    # Hero Header
    st.markdown(
        """
        <div class="hero-container">
            <div class="hero-title">🛡️ Scam Shield (स्कैम शील्ड)</div>
            <div class="hero-subtitle">
                Instant, elder-friendly fraud protection for WhatsApp, SMS, and email messages in India.
                Simple answers. Zero confusing tech jargon.
            </div>
            <div>
                <span class="helpline-badge">🚨 National Cyber Helpline: Dial 1930 (Free & 24x7)</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Instructions & Quick Samples Section
    st.markdown("#### 💡 Quick Test: Click a sample message or paste your own below")

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        if st.button("⚡ Electricity Scam", use_container_width=True):
            st.session_state["message_input"] = SAMPLE_MESSAGES["⚡ Electricity Disconnection"]
    with col2:
        if st.button("🏦 Bank KYC APK", use_container_width=True):
            st.session_state["message_input"] = SAMPLE_MESSAGES["🏦 SBI / YONO KYC Expiry APK"]
    with col3:
        if st.button("🎁 ₹25L KBC Lottery", use_container_width=True):
            st.session_state["message_input"] = SAMPLE_MESSAGES["🎁 WhatsApp ₹25 Lakh KBC Lottery"]
    with col4:
        if st.button("👮 Digital Arrest", use_container_width=True):
            st.session_state["message_input"] = SAMPLE_MESSAGES["👮 Digital Arrest / Courier Threat"]
    with col5:
        if st.button("✅ Safe Bank SMS", use_container_width=True):
            st.session_state["message_input"] = SAMPLE_MESSAGES["✅ Legitimate Bank Transaction"]

    # Main Message Input
    user_message = st.text_area(
        label="Paste suspicious message here (supports English, हिंदी, and Hinglish):",
        value=st.session_state["message_input"],
        height=160,
        placeholder="Example: Dear customer your electricity bill is due tonight. Call 9876543210 to avoid power cut...",
        help="You can paste SMS, WhatsApp forwards, suspicious emails, or offer messages."
    )

    # Privacy Callout
    st.caption(
        "🔒 **Privacy Notice**: Messages are analyzed in real time. "
        "When AI analysis is active, message content is evaluated using Google Gemini. "
        "Never submit sensitive personal credentials like bank passwords, MPINs, or OTPs."
    )

    # Analyze Button
    analyze_clicked = st.button("🔍 Analyse Message (संदेश की जांच करें)", type="primary", use_container_width=True)

    if analyze_clicked:
        cleaned_text = user_message.strip()
        
        if not cleaned_text:
            st.warning("⚠️ Please paste or type a message first to analyze.")
        else:
            # Step 1: Execute rule-based checks
            rule_results = analyze_rules(cleaned_text)
            api_key = get_gemini_api_key()

            raw_analysis = None
            error_info = None

            # Streamlit loading spinner strictly wraps the analysis execution
            with st.spinner("Analyzing message safety with Scam Shield intelligence..."):
                if api_key:
                    raw_analysis = analyze_with_gemini(cleaned_text, rule_results, api_key)
                    if "error_type" in raw_analysis:
                        error_info = raw_analysis
                        # Fallback to transparent heuristics
                        analysis = analyze_heuristic_fallback(cleaned_text, rule_results)
                        analysis["is_ai"] = False
                        analysis["fallback_reason"] = error_info["error_title"]
                    else:
                        analysis = raw_analysis
                        analysis["is_ai"] = True
                else:
                    # Fallback when key is missing
                    analysis = analyze_heuristic_fallback(cleaned_text, rule_results)
                    analysis["is_ai"] = False
                    analysis["fallback_reason"] = "No API Key Configured"

            # User-friendly notice when heuristic fallback was used
            if not analysis.get("is_ai", False):
                st.info(
                    "ℹ️ **Notice**: AI analysis is temporarily unavailable. "
                    "Scam Shield is using its built-in rule-based checks."
                )

            # ==============================================================================
            # Result Card Presentation
            # ==============================================================================
            verdict = analysis.get("verdict", "SUSPICIOUS").upper()
            scam_type = analysis.get("scam_type", "Suspicious Alert")
            explanation = analysis.get("explanation", "Exercise high caution.")
            red_flags = analysis.get("red_flags", [])
            recommended_actions = analysis.get("recommended_actions", [])
            confidence = analysis.get("confidence", "MEDIUM")
            is_ai = analysis.get("is_ai", False)

            # Visual styling depending on verdict and mode
            mode_tag = "GEMINI 3.5 FLASH LITE" if is_ai else "HEURISTIC ANALYSIS"
            if verdict == "SCAM":
                verdict_class = "verdict-scam"
                verdict_icon = "🚨"
                verdict_badge = f"HIGH DANGER - SCAM DETECTED ({mode_tag})"
            elif verdict == "SAFE":
                verdict_class = "verdict-safe"
                verdict_icon = "🛡️"
                verdict_badge = f"NO MAJOR WARNING SIGNS FOUND ({mode_tag})"
            else: # SUSPICIOUS
                verdict_class = "verdict-suspicious"
                verdict_icon = "⚠️"
                verdict_badge = f"SUSPICIOUS - PROCEED WITH CAUTION ({mode_tag})"

            mode_label = "🤖 AI Assisted (Gemini 3.5 Flash Lite)" if is_ai else "⚙️ Rule-Based Heuristics (Offline Fallback)"

            # Sanitize all dynamic content to prevent HTML injection and layout breaks
            safe_verdict_badge = html.escape(str(verdict_badge))
            safe_confidence = html.escape(str(confidence))
            safe_mode_label = html.escape(str(mode_label))
            safe_scam_type = html.escape(str(scam_type))
            safe_explanation = html.escape(str(explanation))

            # Build Warning Signs / Red Flags items (escape content, handle empty list)
            if red_flags:
                valid_flags = [str(f).strip() for f in red_flags if str(f).strip()]
            else:
                valid_flags = []

            if valid_flags:
                flags_html = "".join(
                    f'<div class="red-flag-item">🚩 {html.escape(flag)}</div>'
                    for flag in valid_flags
                )
            else:
                flags_html = '<div class="red-flag-item" style="border-left-color: #94a3b8; background: rgba(148, 163, 184, 0.1);">No specific warning signs identified.</div>'

            # Build Practical Next Steps items (escape content, handle empty list)
            if recommended_actions:
                valid_actions = [str(a).strip() for a in recommended_actions if str(a).strip()]
            else:
                valid_actions = []

            if valid_actions:
                actions_html = "".join(
                    f'<div class="action-step-item">✅ {html.escape(act)}</div>'
                    for act in valid_actions
                )
            else:
                actions_html = '<div class="action-step-item" style="border-left-color: #94a3b8; background: rgba(148, 163, 184, 0.1);">No immediate action required. Stay vigilant.</div>'

            # Construct verdict card HTML without leading spaces or blank lines so Markdown
            # engines never misinterpret sections as indented code blocks (<pre><code>)
            card_html = (
                f'<div class="verdict-card {verdict_class}">'
                f'<div class="verdict-header">'
                f'<div class="verdict-title"><span>{verdict_icon}</span> <span>{safe_verdict_badge}</span></div>'
                f'<div style="font-weight: 700; opacity: 0.9;">Confidence: {safe_confidence} | Mode: {safe_mode_label}</div>'
                f'</div>'
                f'<div class="verdict-type">🏷️ Category: <strong>{safe_scam_type}</strong></div>'
                f'<div class="verdict-explanation"><strong>What this means:</strong> {safe_explanation}</div>'
                f'<div class="result-section-title">⚠️ Warning Signs Identified:</div>'
                f'{flags_html}'
                f'<div class="result-section-title">🛡️ Practical Next Steps For You:</div>'
                f'{actions_html}'
                f'</div>'
            )
            st.markdown(card_html, unsafe_allow_html=True)

            # Explicit Disclaimers (Required by safety principles)
            if verdict == "SAFE":
                st.markdown(
                    '<div class="disclaimer-box">'
                    '<strong>🛡️ IMPORTANT SAFETY NOTICE FOR SAFE RESULTS:</strong><br>'
                    'A \'SAFE\' verdict explicitly means that no known major warning signs or threat patterns were '
                    'identified in the text you supplied. This is <strong>NOT</strong> an absolute guarantee that the '
                    'sender is legitimate. Always verify independently and <strong>NEVER</strong> share your bank '
                    'OTP, PIN, or password with anyone.'
                    '</div>',
                    unsafe_allow_html=True
                )

            st.markdown(
                '<div class="disclaimer-box">'
                '<strong>⚖️ Independent Safety Tool:</strong> Scam Shield is an educational and fraud-prevention aid. '
                'This result is an automated AI risk assessment and has <strong>NOT</strong> been verified or endorsed by '
                'any bank, police authority, or government department.'
                '</div>',
                unsafe_allow_html=True
            )

            # ==============================================================================
            # Transparent Rule-Based Breakdown
            # ==============================================================================
            with st.expander("🔍 See Transparent Rule-Based Checks (पारदर्शी नियम जांच)"):
                st.markdown(
                    "Scam Shield runs direct heuristic checks for India-specific scam indicators before combining signals with Gemini AI:"
                )
                
                checks = [
                    ("Urgent Threats & Fear Tactics", "⏱️", "Urgency / Disconnection / Arrest keywords in English & Hindi"),
                    ("Credential & KYC Demands", "🔑", "OTP, PIN, Password, Aadhaar or KYC requests"),
                    ("Suspicious Links & Downloads", "🔗", "Shortened URLs, lookalike domains, or .APK file downloads"),
                    ("Payment Demands & Lottery Traps", "💸", "Advance fees, lottery prizes, or QR code payment tricks"),
                    ("Official Organization Mentions", "🏛️", "Electricity boards, banks, police or government agencies")
                ]

                found_categories = {f["category"]: f for f in rule_results.get("findings", [])}

                for name, icon, desc in checks:
                    if name in found_categories:
                        f = found_categories[name]
                        st.markdown(f"**{icon} {name}**: 🔴 <span style='color: #f87171; font-weight:600;'>FLAGGED</span> — {', '.join(f['details'])}", unsafe_allow_html=True)
                    else:
                        st.markdown(f"**{icon} {name}**: 🟢 <span style='color: #4ade80;'>Clear</span> — No obvious triggers found", unsafe_allow_html=True)

    # Footer
    st.markdown("---")
    fcol1, fcol2, fcol3 = st.columns(3)
    with fcol1:
        st.markdown("##### 📞 Did you lose money?")
        st.caption("Call the National Cyber Helpline immediately at **1930** to freeze fraudulent bank transfers within the golden hour.")

    with fcol2:
        st.markdown("##### 🌐 Official Portals")
        st.caption("File official complaints at [cybercrime.gov.in](https://cybercrime.gov.in) and report spam numbers on [sancharsaathi.gov.in](https://sancharsaathi.gov.in).")

    with fcol3:
        st.markdown("##### 🛡️ Scam Shield MVP")
        st.caption("Designed for parents, grandparents, and digital newcomers across India. Protect your family.")


if __name__ == "__main__":
    render_app()
