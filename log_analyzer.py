import anthropic
import os
import re
import requests
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

def read_log_file(filepath):
    with open(filepath, 'r') as f:
        return f.read()

def detect_log_type(log_content):
    if "sshd" in log_content or "Failed password" in log_content:
        return "SSH Authentication Log"
    elif "HTTP" in log_content or "GET" in log_content:
        return "Apache Web Server Log"
    else:
        return "Unknown Log Type"

def extract_ips(log_content):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return list(set(re.findall(ip_pattern, log_content)))

def check_ip_reputation(ip):
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )
        data = response.json()
        return {
            "ip": ip,
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "org": data.get("org", "Unknown")
        }
    except:
        return {"ip": ip, "country": "Unknown", "isp": "Unknown"}

def analyze_logs(log_content, ip_info, log_type):
    ip_context = "\n".join([
        f"IP {info['ip']}: {info['country']} | {info['isp']}"
        for info in ip_info
    ])

    today = datetime.now().strftime("%Y-%m-%d")

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        messages=[
            {
                "role": "user",
                "content": f"""You are a cybersecurity expert analyzing {log_type}.

STRICT RULES - YOU MUST FOLLOW EXACTLY:
- Start the report with EXACTLY this header and nothing else before it:

# 🔒 Security Log Analysis Report
**Date:** {today}
**Analyst:** Deekshitha Siddagoni
**Tool:** AI Log Detector
**Log Type:** {log_type}

---

- NEVER use "Automated Threat Detection System"
- NEVER use any other analyst name except "Deekshitha Siddagoni"
- Always end the report with: *Report by Deekshitha Siddagoni | AI Log Detector*

IP Address Information:
{ip_context}

Analyze these logs and for each threat provide:
1. Threat Type
2. Severity (Critical/High/Medium/Low)
3. Threat Score (1-10)
4. Source IP and location
5. Timeline of events
6. Recommended immediate action

Also provide:
- Overall Risk Score (1-10)
- Top 3 priority actions
- Executive summary

Logs to analyze:
{log_content}"""
            }
        ]
    )
    return message.content[0].text

def save_report(analysis, ip_info, log_type, output_file):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(output_file, 'w') as f:
        f.write(f"=== SECURITY ANALYSIS REPORT ===\n")
        f.write(f"Generated: {timestamp}\n")
        f.write(f"Analyst: Deekshitha Siddagoni\n")
        f.write(f"Tool: AI Log Detector\n")
        f.write(f"Log Type: {log_type}\n")
        f.write(f"{'='*40}\n\n")
        f.write("=== IP REPUTATION CHECK ===\n")
        for info in ip_info:
            f.write(f"IP: {info['ip']}\n")
            f.write(f"   Country: {info['country']}\n")
            f.write(f"   ISP: {info['isp']}\n\n")
        f.write(f"{'='*40}\n\n")
        f.write(analysis)
    print(f"\n✅ Report saved to {output_file}")

def analyze_file(log_file, report_file):
    print(f"\n{'='*50}")
    print(f"🔍 Reading: {log_file}")
    logs = read_log_file(log_file)

    log_type = detect_log_type(logs)
    print(f"📋 Detected: {log_type}")

    print("🌍 Checking IP reputations...")
    ips = extract_ips(logs)
    ip_info = [check_ip_reputation(ip) for ip in ips]
    for info in ip_info:
        print(f"   {info['ip']} → {info['country']} | {info['isp']}")

    print("🤖 Analyzing with AI...")
    analysis = analyze_logs(logs, ip_info, log_type)

    print(f"\n=== AI Security Analysis: {log_type} ===\n")
    print(analysis)

    save_report(analysis, ip_info, log_type, report_file)

def main():
    os.makedirs("results", exist_ok=True)

    # Analyze SSH logs
    analyze_file(
        "sample_logs/auth.log",
        "results/ssh_report.txt"
    )

    # Analyze Apache logs
    analyze_file(
        "sample_logs/apache.log",
        "results/apache_report.txt"
    )

if __name__ == "__main__":
    main()