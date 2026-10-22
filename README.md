# 🛡️ Scam Shield (स्कैम शील्ड)

> **Accessible, elder-friendly fraud protection for WhatsApp, SMS, and email messages in India.**

Scam Shield is an AI-powered safety tool built specifically for parents, grandparents, and first-time smartphone users across India. It analyzes suspicious messages in English, Hindi, and Hinglish to detect common Indian cyber scams — such as electricity bill disconnection threats, fake bank KYC APK downloads, WhatsApp lottery fraud, and "Digital Arrest" impersonation.

---

## 🚀 Quick Start Guide (For Beginners)

Follow these simple steps to run Scam Shield on your computer.

### Step 1: Open Terminal / PowerShell in this folder
Ensure your terminal is inside the `scam-shield` directory:
```powershell
cd scam-shield
```

### Step 2: (Optional but Recommended) Add Your Gemini API Key
Scam Shield works out-of-the-box in **Rule-Based Heuristic Mode**, but adding a free Google Gemini API key enables deep AI reasoning with `gemini-3.5-flash-lite`.

1. Get a free API key at [Google AI Studio](https://aistudio.google.com/app/apikey).
2. Copy the `.env.example` file and name the copy `.env`:
   ```powershell
   Copy-Item .env.example .env
   ```
3. Open `.env` in Notepad or your editor and replace `your_gemini_api_key_here` with your actual key:
   ```env
   GEMINI_API_KEY="AIzaSyYourActualKeyGoesHere"
   ```
*(Note: You can also paste your key into the app's sidebar during your session without editing files).*

### Step 3: Run the Streamlit Application
Run this exact command in your terminal:
```powershell
.venv\Scripts\streamlit run app.py
```

Your browser will automatically open to `http://localhost:8501`.

---

## 📁 Understanding the Project Files (Beginner-Friendly)

Here is a simple explanation of every file in this repository:

| File | What it does |
| :--- | :--- |
| **`app.py`** | The main application code. It contains the user interface (built with Streamlit), the transparent rule-based scam scanner, and the Gemini AI analysis integration. |
| **`requirements.txt`** | A shopping list of Python packages needed for the app (`streamlit`, `google-genai`, `python-dotenv`, `pydantic`). |
| **`.env.example`** | A template showing where your secret Gemini API key should go. It serves as a placeholder so you don't commit your real key to GitHub. |
| **`.gitignore`** | Tells Git to ignore sensitive files (like your real `.env` key, the virtual environment `.venv/`, and temporary cache files). |
| **`README.md`** | This guide! Contains setup instructions and system documentation. |

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
Rule matches alone are **never** treated as definitive proof of a scam. For example, a real bank transaction SMS mentions a bank name and amount, but is completely legitimate. Gemini evaluates the full conversational context and returns a structured verdict.

---

## 🛡️ Core Safety Principles

1. **Cautious by Design**: If a message's intent is uncertain or incomplete, Scam Shield assigns **SUSPICIOUS** rather than SAFE.
2. **Explicit SAFE Meaning**: A `SAFE` result explicitly means *no major warning signs were found in the supplied text*. It is **never** an absolute guarantee of sender legitimacy.
3. **No False Authority**: Scam Shield never claims that any message has been verified or endorsed by a bank, police agency, or government department.
4. **Zero-Storage Privacy**: Submitted text is processed in real time and is **never** logged, saved, or persisted.

---

## 🇮🇳 Emergency Helplines (India)

If you or someone in your family has fallen victim to online financial fraud:
- **National Cybercrime Helpline**: Dial **1930** immediately (Golden Hour response to freeze stolen funds).
- **Online Complaint Portal**: [cybercrime.gov.in](https://cybercrime.gov.in)
- **Chakshu Fraud Communication Reporting**: [sancharsaathi.gov.in](https://sancharsaathi.gov.in)
- **RBI Banking Ombudsman**: Dial **14448**
