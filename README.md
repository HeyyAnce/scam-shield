# 🛡️ Scam Shield (स्कैम शील्ड)

> **Accessible, elder-friendly fraud protection for WhatsApp, SMS, and email messages in India.**

Scam Shield is a fraud-prevention safety tool built specifically for parents, grandparents, and first-time smartphone users across India. It analyzes suspicious messages in English, Hindi, and Hinglish to detect common Indian cyber scams — such as electricity bill disconnection threats, fake bank KYC APK downloads, WhatsApp lottery fraud, and "Digital Arrest" impersonation.

Live Web App: [https://ideaforge-scam-shield.streamlit.app/](https://ideaforge-scam-shield.streamlit.app/)

---

## 👥 Using Scam Shield (For Public Users)

**Ordinary visitors and end users do NOT need an API key.** 

To analyze a message:
1. Open [Scam Shield](https://ideaforge-scam-shield.streamlit.app/).
2. Paste any suspicious message (or click one of the quick test sample buttons).
3. Click **Analyse Message (संदेश की जांच करें)** to receive an instant, plain-language assessment and practical safety actions.

---

## ⚙️ Configuration & Deployment Guide

Scam Shield uses a secure, centralized API-key resolution system with an automatic rule-based offline fallback.

### 🌐 Cloud Deployment (Streamlit Community Cloud)
On deployed Streamlit environments, the application owner configures the Gemini API key centrally through server-side Secrets. Visitors never supply their own keys.

1. Open your app dashboard on [Streamlit Community Cloud](https://share.streamlit.io/).
2. Navigate to **App settings** → **Secrets**.
3. Add your Gemini API key:
   ```toml
   GEMINI_API_KEY = "your_actual_gemini_api_key_here"
   ```
4. Save the secret. Streamlit securely injects this at runtime (`st.secrets["GEMINI_API_KEY"]`). No `.env` file is required on the hosting server.

### 💻 Local Development Setup
Developers running the app locally can configure their key using an untracked `.env` file:

1. **Clone the repository and enter the directory**:
   ```powershell
   cd scam-shield
   ```
2. **Install dependencies**:
   ```powershell
   .venv\Scripts\pip install -r requirements.txt
   ```
3. **Configure your local environment key (optional)**:
   - Copy `.env.example` to create your private `.env` file:
     ```powershell
     Copy-Item .env.example .env
     ```
   - Open `.env` and set your key:
     ```env
     GEMINI_API_KEY="your_actual_gemini_api_key_here"
     ```
   - *Security Note*: `.env` is strictly ignored by `.gitignore` and must **never** be committed to version control. Keep `.env.example` as a placeholder template only.
4. **Launch the app**:
   ```powershell
   .venv\Scripts\streamlit run app.py
   ```

### 🛡️ Automatic Heuristic Fallback
If no API key is configured or the Gemini AI service is temporarily unavailable:
- Scam Shield automatically switches to its built-in **Rule-Based Heuristic Engine**.
- The app displays a clear notice: *"AI analysis is temporarily unavailable. Scam Shield is using its built-in rule-based checks."*
- Full risk appraisal and India-specific scam pattern detection continue to function without crashing or blocking users.

---

## 📁 Understanding the Project Files

| File | What it does |
| :--- | :--- |
| **`app.py`** | The main application code. It contains the user interface, centralized API-key loading, transparent rule-based heuristics, and Gemini AI analysis. |
| **`requirements.txt`** | Python dependencies (`streamlit`, `google-genai`, `python-dotenv`, `pydantic`). |
| **`.env.example`** | Safe template showing where local developers can configure `GEMINI_API_KEY`. Contains only placeholder values. |
| **`.gitignore`** | Ensures sensitive files (local `.env`, `.streamlit/secrets.toml`, virtual environments `.venv/`, and caches) are never committed. |
| **`README.md`** | Project documentation and configuration instructions. |

---

## 🧠 How Scam Shield Works

Scam Shield combines two layers of defense to protect users:

```
                  ┌──────────────────────────────────────────────┐
                  │          User Pastes Message                 │
                  │   (SMS / WhatsApp in Eng, हिंदी, Hinglish)    │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │      1. Transparent Heuristic Checks         │
                  │  • Urgency & fear tactics                    │
                  │  • OTP / PIN / password harvesting           │
                  │  • Shortened links & malicious .APK files    │
                  │  • Advance fee & UPI payment demands         │
                  │  • Bank / Police / Electricity impersonation │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │      2. Google Gemini 3.5 Flash Lite AI      │
                  │  (Uses server secrets or local .env key)     │
                  │  • Evaluates context & nuanced phrasing      │
                  │  • Distinguishes real bank SMS from scams    │
                  │  • Outputs structured verdict + simple steps │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │          Clear Verdict & Next Steps          │
                  │       🚨 SCAM  |  ⚠️ SUSPICIOUS  |  🛡️ SAFE   │
                  │  • 1-sentence plain-language explanation     │
                  │  • 2–3 specific red flags                    │
                  │  • Practical next steps & 1930 helpline      │
                  └──────────────────────────────────────────────┘
```

### 1. Transparent Rule-Based Checks
The message is immediately scanned for known scam indicators:
- **Urgent Threats & Panic Inducers**: "disconnected tonight", "aaj raat bijli kat jayegi", "digital arrest", "FIR filed".
- **Sensitive Credentials**: Demands for OTP, MPIN, CVV, passwords, or immediate KYC update links.
- **Dangerous URLs & APKs**: Shortened links (`bit.ly`, `tinyurl.com`), raw IP addresses, and `.apk` downloads.
- **Advance Fee Traps**: Unsolicited lottery prizes, "won 25 lakh KBC", and scams asking users to scan QR codes or enter UPI PINs to "receive" money.
- **Organization Impersonation**: State electricity boards (Mahavitaran, Bescom, BSES, etc.), major banks (SBI, HDFC), or law enforcement.

### 2. Gemini 3.5 Flash Lite Contextual Analysis
Rule matches alone are **never** treated as definitive proof of a scam. For example, a real bank transaction SMS mentions a bank name and amount, but is completely legitimate. When enabled, Gemini evaluates full conversational context and returns a structured verdict. If Gemini is unavailable, the rule-based heuristics serve as an instant, transparent fallback.

---

## 🛡️ Core Safety Principles

1. **Cautious by Design**: If a message's intent is uncertain or incomplete, Scam Shield assigns **SUSPICIOUS** rather than SAFE.
2. **Explicit SAFE Meaning**: A `SAFE` result explicitly means *no major warning signs were found in the supplied text*. It is **never** an absolute guarantee of sender legitimacy.
3. **No False Authority**: Scam Shield never claims that any message has been verified or endorsed by a bank, police agency, or government department.
4. **Privacy-Conscious Processing**: Messages are processed in real time for fraud detection. When AI analysis is enabled, message content is evaluated via Google Gemini. Users are advised never to enter private credentials, full payment card numbers, or passwords.

---

## 🇮🇳 Emergency Helplines (India)

If you or someone in your family has fallen victim to online financial fraud:
- **National Cybercrime Helpline**: Dial **1930** immediately (Golden Hour response to freeze stolen funds).
- **Online Complaint Portal**: [cybercrime.gov.in](https://cybercrime.gov.in)
- **Chakshu Fraud Communication Reporting**: [sancharsaathi.gov.in](https://sancharsaathi.gov.in)
- **RBI Banking Ombudsman**: Dial **14448**
