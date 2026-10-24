# Scam Shield

Scam Shield checks a suspicious SMS, WhatsApp or email message and tells you if it looks like a scam. It explains why in plain language and says what to do next. It is built for people in India, especially parents, grandparents and first-time smartphone users.

Live app: https://ideaforge-scam-shield.streamlit.app/

## What it does

You paste the text of a message. You get one of three results:

| Result | Meaning |
| :--- | :--- |
| **Likely scam** | Strong scam signs were found. |
| **Needs verification** | Some signs are worrying, or it is unclear. Check another way before acting. |
| **No clear scam signs found** | Nothing alarming was found. This does not prove the sender is genuine. |

Along with the result you see the warning signs, numbered steps to take, and how the message was checked.

- The page can be switched between English and Hindi, and between light and dark mode.
- You can paste messages in English, Hinglish or Hindi.
- It reads the text only. It cannot tell who really sent a message, and it does not stop payments.

## How a message is checked

1. **Rules** look for known scam signs: urgency and threats, requests for OTP or PIN, suspicious links and APK files, advance-fee and UPI tricks, and links that copy a real bank's name.
2. **Reference examples** from `data/dataset` are compared with the message.
3. **Google Gemini** reads the full message when an API key is set up.
4. **A decision step** combines all of the above into one result.

If there is no API key, or Gemini is not available, the app still works with the rules and reference examples. The result says that the AI check was not used.

## The data

The `data/dataset` folder holds the English and Hinglish example messages, a list of official bank and government websites, and the sources. Open any `.csv` file in Excel. See `data/dataset/README.txt` for details.

- Most example messages are synthetic: written for testing, with made-up names, numbers and links. The rest are real messages from public collections.
- The messages are used to find similar examples. They are not used to train a model.
- No accuracy figure is claimed for this data.
- In `legit_domains.csv`, only domains marked `checked` are used by the app.

Credits for the public messages and their licences are in `data/dataset/sources.csv`. They come from the UCI SMS Spam Collection (CC BY 4.0), the Hugging Face dataset `anmolshrivastav/scam-ham-india` (Apache-2.0) and the SmishX project (MIT).

## Run it on your computer

You need Python 3.10 or newer. These steps are for Windows PowerShell.

```powershell
git clone https://github.com/HeyyAnce/scam-shield.git
cd scam-shield
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

The app opens at http://localhost:8501.

The Gemini key is optional. To use it, copy `.env.example` to `.env` and set `GEMINI_API_KEY`. Never commit the `.env` file.

## Put it online (Streamlit Community Cloud)

Add the key in the app's settings under **Secrets**:

```toml
GEMINI_API_KEY = "your_key_here"
```

Visitors do not need a key of their own.

## Project files

| Path | What it does |
| :--- | :--- |
| `app.py` | The page: input, results, language and theme switches. |
| `src/pipeline.py` | Runs the steps in order. |
| `src/rule_engine.py` | The rules, and the check for official links. |
| `src/dataset_loader.py` | Loads and validates the dataset. |
| `src/reference_matcher.py` | Finds similar example messages. |
| `src/gemini_client.py` | Talks to Gemini. |
| `src/decision_engine.py` | Combines everything into one result. |
| `src/config.py` | Settings and file paths. |
| `data/dataset/` | The example messages, official websites and sources. |
| `.streamlit/config.toml` | Page theme. |
| `.env.example` | Template for the local `.env` file. |

## Privacy

When the AI check is on, the text of your message is sent to Google Gemini. Do not paste passwords, PINs, OTPs or card numbers.

## If you have been scammed

- National Cybercrime Helpline: call **1930** straight away.
- Report online: https://cybercrime.gov.in
- Report a fraud call or message (Chakshu): https://sancharsaathi.gov.in
- Help with a complaint about your bank: RBI contact centre, toll-free **14448**.

Scam Shield is a project made for a hackathon. It is not connected to any bank, police body or government department, and none of them has checked or approved its results.
