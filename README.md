AI-Powered Security Log Analyzer

An intelligent cybersecurity tool that analyzes security logs and automatically detects threats using Claude AI (Anthropic).

---

## What Threats Does It Detect?

**SSH Logs**
- Brute force attacks
- Unauthorized root access
- Internal network attacks
- Tor exit node reconnaissance
- Suspicious user behavior
- Privilege escalation attempts

**Apache Web Server Logs**
- SQL injection attacks
- XSS (Cross-Site Scripting)
- Directory traversal attacks
- Sensitive file exposure (.env, .git)
- Reconnaissance and scanning

---

## Key Features

- Reads real log files automatically
- Detects log type automatically (SSH or Apache)
- AI analyzes and explains every threat in plain English
- IP reputation checking with geographic location
- Threat scoring system (1-10)
- Severity levels (Critical/High/Medium/Low)
- Generates professional incident reports
- Saves reports automatically with timestamp
- GDPR/CCPA compliance notes included
- Executive summary for management reporting

---

## Tools and Technologies

| Tool | Purpose |
|------|---------|
| Python 3 | Core programming language |
| Claude AI (Anthropic) | AI threat analysis engine |
| ip-api.com | IP reputation and geolocation |
| python-dotenv | Secure API key management |
| requests | HTTP library for IP lookups |

---

## How to Run

**1. Clone the repository**
git clone https://github.com/Deekshitha-02/ai-log-detector.git
cd ai-log-detector

**2. Install dependencies**
pip install anthropic python-dotenv requests

**3. Add your API key**

Create a `.env` file:
ANTHROPIC_API_KEY=your-key-here

**4. Add your log files**

Place your log files in the `sample_logs/` folder

**5. Run the analyzer**
python3 log_analyzer.py

**6. View your reports**

Find generated reports in the `results/` folder

---

## Project Structure

| File | Description |
|------|-------------|
| log_analyzer.py | Main AI analysis script |
| sample_logs/auth.log | Sample SSH authentication log |
| sample_logs/apache.log | Sample Apache web server log |
| results/ssh_report.txt | SSH threat analysis report |
| results/apache_report.txt | Web server threat analysis report |
| .env | API key (not uploaded to GitHub) |
| .gitignore | Protects sensitive files |

---

## Sample Output
Reading: sample_logs/auth.log
Detected: SSH Authentication Log
Checking IP reputations...
192.168.1.100 → Unknown | Unknown
185.220.101.1 → Germany | Stiftung Erneuerbare Freiheit
Analyzing with AI...
THREAT 1: Brute Force + Root Compromise
Score: 9.5/10 | Severity: CRITICAL
THREAT 2: Internal Brute Force
Score: 7.5/10 | Severity: HIGH
Report saved to results/ssh_report.txt

---

## Security Note

API keys are stored in a `.env` file and never uploaded to GitHub. The `.gitignore` file ensures sensitive data stays local.

---
## Disclaimer

This project is for educational and portfolio purposes only.
Do not upload real sensitive logs or API keys.
Sample logs included are fictional and created for demonstration.

---

## Author

**Deekshitha Siddagoni**

Cybersecurity Analyst | AI Security Tools | Python Automation

---

## Medium Article

Coming soon — full walkthrough of how this tool was built and how it can be used in real IT security environments.
